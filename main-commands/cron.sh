#!/bin/bash

# Usage: --cron (-c)
# Description: Sign/renew non-existent/changed/expiring certificates.
command_sign_domains() {
  init_system
  hookscript_bricker_hook

  # Call startup hook
  [[ -n "${HOOK}" ]] && ("${HOOK}" "startup_hook" || _exiterr 'startup_hook hook returned with non-zero exit code')

  if [ ! -d "${CHAINCACHE}" ]; then
    echo " + Creating chain cache directory ${CHAINCACHE}"
    mkdir "${CHAINCACHE}"
  fi

  if [[ -n "${PARAM_DOMAIN:-}" ]]; then
    DOMAINS_TXT="$(_mktemp)"
    if [[ -n "${PARAM_ALIAS:-}" ]]; then
      printf -- "${PARAM_DOMAIN} > ${PARAM_ALIAS}" > "${DOMAINS_TXT}"
    else
      printf -- "${PARAM_DOMAIN}" > "${DOMAINS_TXT}"
    fi
  elif [[ -e "${DOMAINS_TXT}" ]]; then
    if [[ ! -r "${DOMAINS_TXT}" ]]; then
      _exiterr "domains.txt found but not readable"
    fi
  else
    _exiterr "domains.txt not found and --domain not given"
  fi

  # Generate certificates for all domains found in domains.txt. Check if existing certificate are about to expire
  ORIGIFS="${IFS}"
  IFS=$'\n'
  for line in $(<"${DOMAINS_TXT}" tr -d '\r' | awk '{print tolower($0)}' | _sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$//g' -e 's/[[:space:]]+/ /g' -e 's/([^ ])>/\1 >/g' -e 's/> />/g' | (grep -vE '^(#|$)' || true)); do
    reset_configvars
    IFS="${ORIGIFS}"
    alias="$(grep -Eo '>[^ ]+' <<< "${line}" || true)"
    line="$(_sed -e 's/>[^ ]+[ ]*//g' <<< "${line}")"
    aliascount="$(grep -Eo '>' <<< "${alias}" | awk 'END {print NR}' || true )"
    [ ${aliascount} -gt 1 ] && _exiterr "Only one alias per line is allowed in domains.txt!"

    domain="$(printf '%s\n' "${line}" | cut -d' ' -f1)"
    morenames="$(printf '%s\n' "${line}" | cut -s -d' ' -f2-)"
    [ ${aliascount} -lt 1 ] && alias="${domain}" || alias="${alias#>}"
    export alias

    if [[ -z "${morenames}" ]];then
      echo "Processing ${domain}"
    else
      echo "Processing ${domain} with alternative names: ${morenames}"
    fi

    if [ "${alias:0:2}" = "*." ]; then
      _exiterr "Please define a valid alias for your ${domain} wildcard-certificate. See domains.txt-documentation for more details."
    fi

    local certdir="${CERTDIR}/${alias}"
    cert="${certdir}/cert.pem"
    chain="${certdir}/chain.pem"

    force_renew="${PARAM_FORCE:-no}"

    timestamp="$(date +%s)"

    # If there is no existing certificate directory => make it
    if [[ ! -e "${certdir}" ]]; then
      echo " + Creating new directory ${certdir} ..."
      mkdir -p "${certdir}" || _exiterr "Unable to create directory ${certdir}"
    fi

    # read cert config
    # for now this loads the certificate specific config in a subshell and parses a diff of set variables.
    # we could just source the config file but i decided to go this way to protect people from accidentally overriding
    # variables used internally by this script itself.
    if [[ -n "${DOMAINS_D}" ]]; then
      certconfig="${DOMAINS_D}/${alias}"
    else
      certconfig="${certdir}/config"
    fi

    if [ -f "${certconfig}" ]; then
      echo " + Using certificate specific config file!"
      ORIGIFS="${IFS}"
      IFS=$'\n'
      for cfgline in $(
        beforevars="$(_mktemp)"
        aftervars="$(_mktemp)"
        set > "${beforevars}"
        # shellcheck disable=SC1090
        . "${certconfig}"
        set > "${aftervars}"
        diff -u "${beforevars}" "${aftervars}" | grep -E '^\+[^+]'
        rm "${beforevars}"
        rm "${aftervars}"
      ); do
        config_var="$(echo "${cfgline:1}" | cut -d'=' -f1)"
        config_value="$(echo "${cfgline:1}" | cut -d'=' -f2- | tr -d "'")"
	# All settings that are allowed here should also be stored and
	# restored in store_configvars() and reset_configvars()
        case "${config_var}" in
          KEY_ALGO|OCSP_MUST_STAPLE|OCSP_FETCH|OCSP_DAYS|PRIVATE_KEY_RENEW|PRIVATE_KEY_ROLLOVER|KEYSIZE|CHALLENGETYPE|HOOK|PREFERRED_CHAIN|WELLKNOWN|HOOK_CHAIN|OPENSSL_CNF|RENEW_DAYS)
            echo "   + ${config_var} = ${config_value}"
            declare -- "${config_var}=${config_value}"
            ;;
          _) ;;
          *) echo "   ! Setting ${config_var} on a per-certificate base is not (yet) supported" >&2
        esac
      done
      IFS="${ORIGIFS}"
    fi
    verify_config
    hookscript_bricker_hook
    export WELLKNOWN CHALLENGETYPE KEY_ALGO PRIVATE_KEY_ROLLOVER

    skip="no"

    # Allow for external CSR generation
    local csr=""
    if [[ -n "${HOOK}" ]]; then
      csr="$("${HOOK}" "generate_csr" "${domain}" "${certdir}" "${domain} ${morenames}")" || _exiterr 'generate_csr hook returned with non-zero exit code'
      if grep -qE "\-----BEGIN (NEW )?CERTIFICATE REQUEST-----" <<< "${csr}"; then
        altnames="$(extract_altnames "${csr}")"
        domain="$(cut -d' ' -f1 <<< "${altnames}")"
        morenames="$(cut -s -d' ' -f2- <<< "${altnames}")"
        echo " + Using CSR from hook script (real names: ${altnames})"
      else
        csr=""
      fi
    fi

    # Check domain names of existing certificate
    if [[ -e "${cert}" ]]; then
      printf " + Checking domain name(s) of existing cert..."

      certnames="$("${OPENSSL}" x509 -in "${cert}" -text -noout | grep DNS: | _sed 's/DNS://g' | tr -d ' ' | tr ',' '\n' | sort -u | tr '\n' ' ' | _sed 's/ $//')"
      givennames="$(echo "${domain}" "${morenames}"| tr ' ' '\n' | sort -u | tr '\n' ' ' | _sed 's/ $//' | _sed 's/^ //')"

      if [[ "${certnames}" = "${givennames}" ]]; then
        echo " unchanged."
      else
        echo " changed!"
        echo " + Domain name(s) are not matching!"
        echo " + Names in old certificate: ${certnames}"
        echo " + Configured names: ${givennames}"
        echo " + Forcing renew."
        force_renew="yes"
      fi
    fi

    # Check expire date of existing certificate
    if [[ -e "${cert}" ]]; then
      echo " + Checking expire date of existing cert..."
      valid="$("${OPENSSL}" x509 -enddate -noout -in "${cert}" | cut -d= -f2- )"

      printf " + Valid till %s " "${valid}"
      if ("${OPENSSL}" x509 -checkend $((RENEW_DAYS * 86400)) -noout -in "${cert}" > /dev/null 2>&1); then
        printf "(Longer than %d days). " "${RENEW_DAYS}"
        if [[ "${force_renew}" = "yes" ]]; then
          echo "Ignoring because renew was forced!"
        else
          # Certificate-Names unchanged and cert is still valid
          echo "Skipping renew!"
          [[ -n "${HOOK}" ]] && ("${HOOK}" "unchanged_cert" "${domain}" "${certdir}/privkey.pem" "${certdir}/cert.pem" "${certdir}/fullchain.pem" "${certdir}/chain.pem" || _exiterr 'unchanged_cert hook returned with non-zero exit code')
          skip="yes"
        fi
      else
        echo "(Less than ${RENEW_DAYS} days). Renewing!"
      fi
    fi

    local update_ocsp
    update_ocsp="no"

    # Sign certificate for this domain
    if [[ ! "${skip}" = "yes" ]]; then
      update_ocsp="yes"
      [[ -z "${csr}" ]] || printf "%s" "${csr}" > "${certdir}/cert-${timestamp}.csr"
      if [[ "${PARAM_KEEP_GOING:-}" = "yes" ]]; then
        skip_exit_hook=yes
        sign_domain "${certdir}" ${timestamp} ${domain} ${morenames} &
        wait $! || exit_with_errorcode=1
        skip_exit_hook=no
      else
        sign_domain "${certdir}" ${timestamp} ${domain} ${morenames}
      fi
    fi

    if [[ "${OCSP_FETCH}" = "yes" ]]; then
      local ocsp_url
      ocsp_url="$(get_ocsp_url "${cert}")"

      if [[ ! -e "${certdir}/ocsp.der" ]]; then
        update_ocsp="yes"
      elif ! ("${OPENSSL}" ocsp -no_nonce -issuer "${chain}" -verify_other "${chain}" -cert "${cert}" -respin "${certdir}/ocsp.der" -status_age $((OCSP_DAYS*24*3600)) 2>&1 | grep -q "${cert}: good"); then
        update_ocsp="yes"
      fi

      if [[ "${update_ocsp}" = "yes" ]]; then
        echo " + Updating OCSP stapling file"
        ocsp_timestamp="$(date +%s)"
        if grep -qE "^(openssl (0|(1\.0))\.)|(libressl (1|2|3)\.)" <<< "$(${OPENSSL} version | awk '{print tolower($0)}')"; then
          ocsp_log="$("${OPENSSL}" ocsp -no_nonce -issuer "${chain}" -verify_other "${chain}" -cert "${cert}" -respout "${certdir}/ocsp-${ocsp_timestamp}.der" -url "${ocsp_url}" -header "HOST" "$(echo "${ocsp_url}" | _sed -e 's/^http(s?):\/\///' -e 's/\/.*$//g')" 2>&1)" || _exiterr "Error while fetching OCSP information: ${ocsp_log}"
        else
          ocsp_log="$("${OPENSSL}" ocsp -no_nonce -issuer "${chain}" -verify_other "${chain}" -cert "${cert}" -respout "${certdir}/ocsp-${ocsp_timestamp}.der" -url "${ocsp_url}" 2>&1)" || _exiterr "Error while fetching OCSP information: ${ocsp_log}"
        fi
        ln -sf "ocsp-${ocsp_timestamp}.der" "${certdir}/ocsp.der"
        [[ -n "${HOOK}" ]] && (altnames="${domain} ${morenames}" "${HOOK}" "deploy_ocsp" "${domain}" "${certdir}/ocsp.der" "${ocsp_timestamp}" || _exiterr 'deploy_ocsp hook returned with non-zero exit code')
      else
        echo " + OCSP stapling file is still valid (skipping update)"
      fi
    fi
  done
  reset_configvars

  # remove temporary domains.txt file if used
  [[ -n "${PARAM_DOMAIN:-}" ]] && rm -f "${DOMAINS_TXT}"

  [[ -n "${HOOK}" ]] && ("${HOOK}" "exit_hook" || echo 'exit_hook returned with non-zero exit code!' >&2)
  if [[ "${AUTO_CLEANUP}" == "yes" ]]; then
    echo "+ Running automatic cleanup"
    command_cleanup noinit
  fi

  exit "${exit_with_errorcode}"
}
