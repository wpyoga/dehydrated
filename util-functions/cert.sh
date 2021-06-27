#!/bin/bash

# Extracts all subject names from a CSR
# Outputs either the CN, or the SANs, one per line
extract_altnames() {
  csr="${1}" # the CSR itself (not a file)

  if ! <<<"${csr}" "${OPENSSL}" req -verify -noout 2>/dev/null; then
    _exiterr "Certificate signing request isn't valid"
  fi

  reqtext="$( <<<"${csr}" "${OPENSSL}" req -noout -text )"
  if <<<"${reqtext}" grep -q '^[[:space:]]*X509v3 Subject Alternative Name:[[:space:]]*$'; then
    # SANs used, extract these
    altnames="$( <<<"${reqtext}" awk '/X509v3 Subject Alternative Name:/{print;getline;print;}' | tail -n1 )"
    # split to one per line:
    # shellcheck disable=SC1003
    altnames="$( <<<"${altnames}" _sed -e 's/^[[:space:]]*//; s/, /\'$'\n''/g' )"
    # we can only get DNS: ones signed
    if grep -qEv '^(DNS|othername):' <<<"${altnames}"; then
      _exiterr "Certificate signing request contains non-DNS Subject Alternative Names"
    fi
    # strip away the DNS: prefix
    altnames="$( <<<"${altnames}" _sed -e 's/^(DNS:|othername:<unsupported>)//' )"
    printf "%s" "${altnames}" | tr '\n' ' '
  else
    # No SANs, extract CN
    altnames="$( <<<"${reqtext}" grep '^[[:space:]]*Subject:' | _sed -e 's/.*[ /]CN ?= ?([^ /,]*).*/\1/' )"
    printf "%s" "${altnames}"
  fi
}

# Get last issuer CN in certificate chain
get_last_cn() {
  <<<"${1}" _sed 'H;/-----BEGIN CERTIFICATE-----/h;$!d;x' | "${OPENSSL}" x509 -noout -issuer | head -n1 | _sed -e 's/.*[ /]CN ?= ?([^/,]*).*/\1/'
}

# Create certificate for domain(s) and outputs it FD 3
sign_csr() {
  csr="${1}" # the CSR itself (not a file)

  if { true >&3; } 2>/dev/null; then
    : # fd 3 looks OK
  else
    _exiterr "sign_csr: FD 3 not open"
  fi

  shift 1 || true
  export altnames="${*}"

  if [[ ${API} -eq 1 ]]; then
    if [[ -z "${CA_NEW_AUTHZ}" ]] || [[ -z "${CA_NEW_CERT}" ]]; then
      _exiterr "Certificate authority doesn't allow certificate signing"
    fi
  elif [[ ${API} -eq 2 ]] && [[ -z "${CA_NEW_ORDER}" ]]; then
    _exiterr "Certificate authority doesn't allow certificate signing"
  fi

  if [[ -n "${ZSH_VERSION:-}" ]]; then
    local -A challenge_names challenge_uris challenge_tokens authorizations keyauths deploy_args
  else
    local -a challenge_names challenge_uris challenge_tokens authorizations keyauths deploy_args
  fi

  # Initial step: Find which authorizations we're dealing with
  if [[ ${API} -eq 2 ]]; then
    # Request new order and store authorization URIs
    local challenge_identifiers=""
    for altname in ${altnames}; do
      challenge_identifiers+="$(printf '{"type": "dns", "value": "%s"}, ' "${altname}")"
    done
    challenge_identifiers="[${challenge_identifiers%, }]"

    echo " + Requesting new certificate order from CA..."
    order_location="$(signed_request "${CA_NEW_ORDER}" '{"identifiers": '"${challenge_identifiers}"'}' 4>&1 | grep -i ^Location: | cut -d':' -f2- | tr -d ' \t\r\n')"
    result="$(signed_request "${order_location}" "" | jsonsh)"

    order_authorizations="$(echo "${result}" | get_json_array_values authorizations)"
    finalize="$(echo "${result}" | get_json_string_value finalize)"

    local idx=0
    for uri in ${order_authorizations}; do
      authorizations[${idx}]="${uri}"
      idx=$((idx+1))
    done
    echo " + Received ${idx} authorizations URLs from the CA"
  else
    # Copy $altnames to $authorizations (just doing this to reduce duplicate code later on)
    local idx=0
    for altname in ${altnames}; do
      authorizations[${idx}]="${altname}"
      idx=$((idx+1))
    done
  fi

  # Check if authorizations are valid and gather challenge information for pending authorizations
  local idx=0
  for authorization in ${authorizations[*]}; do
    if [[ "${API}" -eq 2 ]]; then
      # Receive authorization ($authorization is authz uri)
      response="$(signed_request "$(echo "${authorization}" | _sed -e 's/\"(.*)".*/\1/')" "" | jsonsh)"
      identifier="$(echo "${response}" | get_json_string_value -p '"identifier","value"')"
      echo " + Handling authorization for ${identifier}"
    else
      # Request new authorization ($authorization is altname)
      identifier="${authorization}"
      echo " + Requesting authorization for ${identifier}..."
      response="$(signed_request "${CA_NEW_AUTHZ}" '{"resource": "new-authz", "identifier": {"type": "dns", "value": "'"${identifier}"'"}}' | jsonsh)"
    fi

    # Check if authorization has already been validated
    if [ "$(echo "${response}" | get_json_string_value status)" = "valid" ]; then
      if [ "${PARAM_FORCE_VALIDATION:-no}" = "yes" ]; then
        echo " + A valid authorization has been found but will be ignored"
      else
        echo " + Found valid authorization for ${identifier}"
        continue
      fi
    fi

    # Find challenge in authorization
    challengeindex="$(echo "${response}" | grep -E '^\["challenges",[0-9]+,"type"\][[:space:]]+"'"${CHALLENGETYPE}"'"' | cut -d',' -f2 || true)"

    if [ -z "${challengeindex}" ]; then
      allowed_validations="$(echo "${response}" | grep -E '^\["challenges",[0-9]+,"type"\]' | sed -e 's/\[[^\]*\][[:space:]]*//g' -e 's/^"//' -e 's/"$//' | tr '\n' ' ')"
      _exiterr "Validating this certificate is not possible using ${CHALLENGETYPE}. Possible validation methods are: ${allowed_validations}"
    fi
    challenge="$(echo "${response}" | get_json_dict_value -p '"challenges",'"${challengeindex}")"

    # Gather challenge information
    challenge_names[${idx}]="${identifier}"
    challenge_tokens[${idx}]="$(echo "${challenge}" | get_json_string_value token)"

    if [[ ${API} -eq 2 ]]; then
      challenge_uris[${idx}]="$(echo "${challenge}" | get_json_string_value url)"
    else
      if [[ "$(echo "${challenge}" | get_json_string_value type)" = "urn:acme:error:unauthorized" ]]; then
        _exiterr "Challenge unauthorized: $(echo "${challenge}" | get_json_string_value detail)"
      fi
      challenge_uris[${idx}]="$(echo "${challenge}" | get_json_dict_value validationRecord | get_json_string_value uri)"
    fi

    # Prepare challenge tokens and deployment parameters
    keyauth="${challenge_tokens[${idx}]}.${thumbprint}"

    case "${CHALLENGETYPE}" in
      "http-01")
        # Store challenge response in well-known location and make world-readable (so that a webserver can access it)
        printf '%s' "${keyauth}" > "${WELLKNOWN}/${challenge_tokens[${idx}]}"
        chmod a+r "${WELLKNOWN}/${challenge_tokens[${idx}]}"
        keyauth_hook="${keyauth}"
        ;;
      "dns-01")
        # Generate DNS entry content for dns-01 validation
        keyauth_hook="$(printf '%s' "${keyauth}" | "${OPENSSL}" dgst -sha256 -binary | urlbase64)"
        ;;
      "tls-alpn-01")
        keyauth_hook="$(printf '%s' "${keyauth}" | "${OPENSSL}" dgst -sha256 -c -hex | awk '{print $NF}')"
        generate_alpn_certificate "${identifier}" "${keyauth_hook}"
        ;;
    esac

    keyauths[${idx}]="${keyauth}"
    deploy_args[${idx}]="${identifier} ${challenge_tokens[${idx}]} ${keyauth_hook}"

    idx=$((idx+1))
  done
  local num_pending_challenges=${idx}
  echo " + ${num_pending_challenges} pending challenge(s)"

  # Deploy challenge tokens
  if [[ ${num_pending_challenges} -ne 0 ]]; then
    echo " + Deploying challenge tokens..."
    if [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" = "yes" ]]; then
      "${HOOK}" "deploy_challenge" ${deploy_args[@]} || _exiterr 'deploy_challenge hook returned with non-zero exit code'
    elif [[ -n "${HOOK}" ]]; then
      # Run hook script to deploy the challenge token
      local idx=0
      while [ ${idx} -lt ${num_pending_challenges} ]; do
        "${HOOK}" "deploy_challenge" ${deploy_args[${idx}]} || _exiterr 'deploy_challenge hook returned with non-zero exit code'
        idx=$((idx+1))
      done
    fi
  fi

  # Validate pending challenges
  local idx=0
  while [ ${idx} -lt ${num_pending_challenges} ]; do
    echo " + Responding to challenge for ${challenge_names[${idx}]} authorization..."

    # Ask the acme-server to verify our challenge and wait until it is no longer pending
    if [[ ${API} -eq 1 ]]; then
      result="$(signed_request "${challenge_uris[${idx}]}" '{"resource": "challenge", "keyAuthorization": "'"${keyauths[${idx}]}"'"}' | jsonsh)"
    else
      result="$(signed_request "${challenge_uris[${idx}]}" '{}' | jsonsh)"
    fi

    reqstatus="$(echo "${result}" | get_json_string_value status)"

    while [[ "${reqstatus}" = "pending" ]] || [[ "${reqstatus}" = "processing" ]]; do
      sleep 1
      if [[ "${API}" -eq 2 ]]; then
        result="$(signed_request "${challenge_uris[${idx}]}" "" | jsonsh)"
      else
        result="$(http_request get "${challenge_uris[${idx}]}" | jsonsh)"
      fi
      reqstatus="$(echo "${result}" | get_json_string_value status)"
    done

    [[ "${CHALLENGETYPE}" = "http-01" ]] && rm -f "${WELLKNOWN}/${challenge_tokens[${idx}]}"
    [[ "${CHALLENGETYPE}" = "tls-alpn-01" ]] && rm -f "${ALPNCERTDIR}/${challenge_names[${idx}]}.crt.pem" "${ALPNCERTDIR}/${challenge_names[${idx}]}.key.pem"

    if [[ "${reqstatus}" = "valid" ]]; then
      echo " + Challenge is valid!"
    else
      [[ -n "${HOOK}" ]] && ("${HOOK}" "invalid_challenge" "${altname}" "${result}" || _exiterr 'invalid_challenge hook returned with non-zero exit code')
      break
    fi
    idx=$((idx+1))
  done

  if [[ ${num_pending_challenges} -ne 0 ]]; then
    echo " + Cleaning challenge tokens..."

    # Clean challenge tokens using chained hook
    [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" = "yes" ]] && ("${HOOK}" "clean_challenge" ${deploy_args[@]} || _exiterr 'clean_challenge hook returned with non-zero exit code')

    # Clean remaining challenge tokens if validation has failed
    local idx=0
    while [ ${idx} -lt ${num_pending_challenges} ]; do
      # Delete challenge file
      [[ "${CHALLENGETYPE}" = "http-01" ]] && rm -f "${WELLKNOWN}/${challenge_tokens[${idx}]}"
      # Delete alpn verification certificates
      [[ "${CHALLENGETYPE}" = "tls-alpn-01" ]] && rm -f "${ALPNCERTDIR}/${challenge_names[${idx}]}.crt.pem" "${ALPNCERTDIR}/${challenge_names[${idx}]}.key.pem"
      # Clean challenge token using non-chained hook
      [[ -n "${HOOK}" ]] && [[ "${HOOK_CHAIN}" != "yes" ]] && ("${HOOK}" "clean_challenge" ${deploy_args[${idx}]} || _exiterr 'clean_challenge hook returned with non-zero exit code')
      idx=$((idx+1))
    done

    if [[ "${reqstatus}" != "valid" ]]; then
      echo " + Challenge validation has failed :("
      _exiterr "Challenge is invalid! (returned: ${reqstatus}) (result: ${result})"
    fi
  fi

  # Finally request certificate from the acme-server and store it in cert-${timestamp}.pem and link from cert.pem
  echo " + Requesting certificate..."
  csr64="$( <<<"${csr}" "${OPENSSL}" req -config "${OPENSSL_CNF}" -outform DER | urlbase64)"
  if [[ ${API} -eq 1 ]]; then
    crt64="$(signed_request "${CA_NEW_CERT}" '{"resource": "new-cert", "csr": "'"${csr64}"'"}' | "${OPENSSL}" base64 -e)"
    crt="$( printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "${crt64}" )"
  else
    result="$(signed_request "${finalize}" '{"csr": "'"${csr64}"'"}' | jsonsh)"
    while :; do
      orderstatus="$(echo "${result}" | get_json_string_value status)"
      case "${orderstatus}"
      in
        "processing" | "pending")
          echo " + Order is ${orderstatus}..."
          sleep 2;
          ;;
        "valid")
          break;
          ;;
        *)
          _exiterr "Order in status ${orderstatus}"
          ;;
      esac
      result="$(signed_request "${order_location}" "" | jsonsh)"
    done

    resheaders="$(_mktemp)"
    certificate="$(echo "${result}" | get_json_string_value certificate)"
    crt="$(signed_request "${certificate}" "" 4>"${resheaders}")"

    if [ -n "${PREFERRED_CHAIN:-}" ]; then
      foundaltchain=0
      altcn="$(get_last_cn "${crt}")"
      altoptions="${altcn}"
      if [ "${altcn}" = "${PREFERRED_CHAIN}" ]; then
        foundaltchain=1
      fi
      if [ "${foundaltchain}" = "0" ]; then
        while read altcrturl; do
          if [ "${foundaltchain}" = "0" ]; then
            altcrt="$(signed_request "${altcrturl}" "")"
            altcn="$(get_last_cn "${altcrt}")"
            altoptions="${altoptions}, ${altcn}"
            if [ "${altcn}" = "${PREFERRED_CHAIN}" ]; then
              foundaltchain=1
              crt="${altcrt}"
            fi
          fi
        done <<< "$(grep -Ei '^link:' "${resheaders}" | grep -Ei 'rel="alternate"' | cut -d'<' -f2 | cut -d'>' -f1)"
      fi
      if [ "${foundaltchain}" = "0" ]; then
        _exiterr "Alternative chain with CN = ${PREFERRED_CHAIN} not found, available options: ${altoptions}"
      fi
      echo " + Using preferred chain with CN = ${altcn}"
    fi
    rm -f "${resheaders}"
  fi

  # Try to load the certificate to detect corruption
  echo " + Checking certificate..."
  _openssl x509 -text <<<"${crt}"

  echo "${crt}" >&3

  unset challenge_token
  echo " + Done!"
}

# grep issuer cert uri from certificate
get_issuer_cert_uri() {
  certificate="${1}"
  "${OPENSSL}" x509 -in "${certificate}" -noout -text | (grep 'CA Issuers - URI:' | cut -d':' -f2-) || true
}

get_issuer_hash() {
  certificate="${1}"
  "${OPENSSL}" x509 -in "${certificate}" -noout -issuer_hash
}

get_ocsp_url() {
  certificate="${1}"
  "${OPENSSL}" x509 -in "${certificate}" -noout -ocsp_uri
}

# walk certificate chain, retrieving all intermediate certificates
walk_chain() {
  local certificate
  certificate="${1}"

  local issuer_cert_uri
  issuer_cert_uri="${2:-}"
  if [[ -z "${issuer_cert_uri}" ]]; then issuer_cert_uri="$(get_issuer_cert_uri "${certificate}")"; fi
  if [[ -n "${issuer_cert_uri}" ]]; then
    # create temporary files
    local tmpcert
    local tmpcert_raw
    tmpcert_raw="$(_mktemp)"
    tmpcert="$(_mktemp)"

    # download certificate
    http_request get "${issuer_cert_uri}" > "${tmpcert_raw}"

    # PEM
    if grep -q "BEGIN CERTIFICATE" "${tmpcert_raw}"; then mv "${tmpcert_raw}" "${tmpcert}"
    # DER
    elif "${OPENSSL}" x509 -in "${tmpcert_raw}" -inform DER -out "${tmpcert}" -outform PEM 2> /dev/null > /dev/null; then :
    # PKCS7
    elif "${OPENSSL}" pkcs7 -in "${tmpcert_raw}" -inform DER -out "${tmpcert}" -outform PEM -print_certs 2> /dev/null > /dev/null; then :
    # Unknown certificate type
    else _exiterr "Unknown certificate type in chain"
    fi

    local next_issuer_cert_uri
    next_issuer_cert_uri="$(get_issuer_cert_uri "${tmpcert}")"
    if [[ -n "${next_issuer_cert_uri}" ]]; then
      printf "\n%s\n" "${issuer_cert_uri}"
      cat "${tmpcert}"
      walk_chain "${tmpcert}" "${next_issuer_cert_uri}"
    fi
    rm -f "${tmpcert}" "${tmpcert_raw}"
  fi
}

# Generate ALPN verification certificate
generate_alpn_certificate() {
  local altname="${1}"
  local acmevalidation="${2}"

  local alpncertdir="${ALPNCERTDIR}"
  if [[ ! -e "${alpncertdir}" ]]; then
    echo " + Creating new directory ${alpncertdir} ..."
    mkdir -p "${alpncertdir}" || _exiterr "Unable to create directory ${alpncertdir}"
  fi

  echo " + Generating ALPN certificate and key for ${1}..."
  tmp_openssl_cnf="$(_mktemp)"
  cat "${OPENSSL_CNF}" > "${tmp_openssl_cnf}"
  printf "\n[SAN]\nsubjectAltName=DNS:%s\n" "${altname}" >> "${tmp_openssl_cnf}"
  printf "1.3.6.1.5.5.7.1.31=critical,DER:04:20:${acmevalidation}\n" >> "${tmp_openssl_cnf}"
  SUBJ="/CN=${altname}/"
  [[ "${OSTYPE:0:5}" = "MINGW" ]] && SUBJ="/${SUBJ}"
  _openssl req -x509 -new -sha256 -nodes -newkey rsa:2048 -keyout "${alpncertdir}/${altname}.key.pem" -out "${alpncertdir}/${altname}.crt.pem" -subj "${SUBJ}" -extensions SAN -config "${tmp_openssl_cnf}"
  chmod g+r "${alpncertdir}/${altname}.key.pem" "${alpncertdir}/${altname}.crt.pem"
  rm -f "${tmp_openssl_cnf}"
}

# Create certificate for domain(s)
sign_domain() {
  local certdir="${1}"
  shift
  timestamp="${1}"
  shift
  domain="${1}"
  altnames="${*}"

  export altnames

  echo " + Signing domains..."
  if [[ ${API} -eq 1 ]]; then
    if [[ -z "${CA_NEW_AUTHZ}" ]] || [[ -z "${CA_NEW_CERT}" ]]; then
      _exiterr "Certificate authority doesn't allow certificate signing"
    fi
  elif [[ ${API} -eq 2 ]] && [[ -z "${CA_NEW_ORDER}" ]]; then
    _exiterr "Certificate authority doesn't allow certificate signing"
  fi

  local privkey="privkey.pem"
  if [[ ! -e "${certdir}/cert-${timestamp}.csr" ]]; then
    # generate a new private key if we need or want one
    if [[ ! -r "${certdir}/privkey.pem" ]] || [[ "${PRIVATE_KEY_RENEW}" = "yes" ]]; then
      echo " + Generating private key..."
      privkey="privkey-${timestamp}.pem"
      local tmp_privkey="$(_mktemp)"
      case "${KEY_ALGO}" in
        rsa) _openssl genrsa -out "${tmp_privkey}" "${KEYSIZE}";;
        prime256v1|secp384r1) _openssl ecparam -genkey -name "${KEY_ALGO}" -out "${tmp_privkey}";;
      esac
      cat "${tmp_privkey}" > "${certdir}/privkey-${timestamp}.pem"
      rm "${tmp_privkey}"
    fi
    # move rolloverkey into position (if any)
    if [[ -r "${certdir}/privkey.pem" && -r "${certdir}/privkey.roll.pem" && "${PRIVATE_KEY_RENEW}" = "yes" && "${PRIVATE_KEY_ROLLOVER}" = "yes" ]]; then
      echo " + Moving Rolloverkey into position....  "
      mv "${certdir}/privkey.roll.pem" "${certdir}/privkey-tmp.pem"
      mv "${certdir}/privkey-${timestamp}.pem" "${certdir}/privkey.roll.pem"
      mv "${certdir}/privkey-tmp.pem" "${certdir}/privkey-${timestamp}.pem"
    fi
    # generate a new private rollover key if we need or want one
    if [[ ! -r "${certdir}/privkey.roll.pem" && "${PRIVATE_KEY_ROLLOVER}" = "yes" && "${PRIVATE_KEY_RENEW}" = "yes" ]]; then
      echo " + Generating private rollover key..."
      case "${KEY_ALGO}" in
        rsa) _openssl genrsa -out "${certdir}/privkey.roll.pem" "${KEYSIZE}";;
        prime256v1|secp384r1) _openssl ecparam -genkey -name "${KEY_ALGO}" -out "${certdir}/privkey.roll.pem";;
      esac
    fi
    # delete rolloverkeys if disabled
    if [[ -r "${certdir}/privkey.roll.pem" && ! "${PRIVATE_KEY_ROLLOVER}" = "yes" ]]; then
      echo " + Removing Rolloverkey (feature disabled)..."
      rm -f "${certdir}/privkey.roll.pem"
    fi

    # Generate signing request config and the actual signing request
    echo " + Generating signing request..."
    SAN=""
    for altname in ${altnames}; do
      SAN="${SAN}DNS:${altname}, "
    done
    SAN="${SAN%%, }"
    local tmp_openssl_cnf
    tmp_openssl_cnf="$(_mktemp)"
    cat "${OPENSSL_CNF}" > "${tmp_openssl_cnf}"
    printf "\n[SAN]\nsubjectAltName=%s" "${SAN}" >> "${tmp_openssl_cnf}"
    if [ "${OCSP_MUST_STAPLE}" = "yes" ]; then
      printf "\n1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05" >> "${tmp_openssl_cnf}"
    fi
    SUBJ="/CN=${domain}/"
    if [[ "${OSTYPE:0:5}" = "MINGW" ]]; then
      # The subject starts with a /, so MSYS will assume it's a path and convert
      # it unless we escape it with another one:
      SUBJ="/${SUBJ}"
    fi
    "${OPENSSL}" req -new -sha256 -key "${certdir}/${privkey}" -out "${certdir}/cert-${timestamp}.csr" -subj "${SUBJ}" -reqexts SAN -config "${tmp_openssl_cnf}"
    rm -f "${tmp_openssl_cnf}"
  fi

  crt_path="${certdir}/cert-${timestamp}.pem"
  # shellcheck disable=SC2086
  sign_csr "$(< "${certdir}/cert-${timestamp}.csr")" ${altnames} 3>"${crt_path}"

  # Create fullchain.pem
  echo " + Creating fullchain.pem..."
  if [[ ${API} -eq 1 ]]; then
    cat "${crt_path}" > "${certdir}/fullchain-${timestamp}.pem"
    local issuer_hash
    issuer_hash="$(get_issuer_hash "${crt_path}")"
    if [ -e "${CHAINCACHE}/${issuer_hash}.chain" ]; then
      echo " + Using cached chain!"
      cat "${CHAINCACHE}/${issuer_hash}.chain" > "${certdir}/chain-${timestamp}.pem"
    else
      echo " + Walking chain..."
      local issuer_cert_uri
      issuer_cert_uri="$(get_issuer_cert_uri "${crt_path}" || echo "unknown")"
      (walk_chain "${crt_path}" > "${certdir}/chain-${timestamp}.pem") || _exiterr "Walking chain has failed, your certificate has been created and can be found at ${crt_path}, the corresponding private key at ${privkey}. If you want you can manually continue on creating and linking all necessary files. If this error occurs again you should manually generate the certificate chain and place it under ${CHAINCACHE}/${issuer_hash}.chain (see ${issuer_cert_uri})"
      cat "${certdir}/chain-${timestamp}.pem" > "${CHAINCACHE}/${issuer_hash}.chain"
    fi
    cat "${certdir}/chain-${timestamp}.pem" >> "${certdir}/fullchain-${timestamp}.pem"
  else
    tmpcert="$(_mktemp)"
    tmpchain="$(_mktemp)"
    awk '{print >out}; /----END CERTIFICATE-----/{out=tmpchain}' out="${tmpcert}" tmpchain="${tmpchain}" "${certdir}/cert-${timestamp}.pem"
    mv "${certdir}/cert-${timestamp}.pem" "${certdir}/fullchain-${timestamp}.pem"
    cat "${tmpcert}" > "${certdir}/cert-${timestamp}.pem"
    cat "${tmpchain}" > "${certdir}/chain-${timestamp}.pem"
    rm "${tmpcert}" "${tmpchain}"
  fi

  # Wait for hook script to sync the files before creating the symlinks
  [[ -n "${HOOK}" ]] && ("${HOOK}" "sync_cert" "${certdir}/privkey-${timestamp}.pem" "${certdir}/cert-${timestamp}.pem" "${certdir}/fullchain-${timestamp}.pem" "${certdir}/chain-${timestamp}.pem" "${certdir}/cert-${timestamp}.csr" || _exiterr 'sync_cert hook returned with non-zero exit code')

  # Update symlinks
  [[ "${privkey}" = "privkey.pem" ]] || ln -sf "privkey-${timestamp}.pem" "${certdir}/privkey.pem"

  ln -sf "chain-${timestamp}.pem" "${certdir}/chain.pem"
  ln -sf "fullchain-${timestamp}.pem" "${certdir}/fullchain.pem"
  ln -sf "cert-${timestamp}.csr" "${certdir}/cert.csr"
  ln -sf "cert-${timestamp}.pem" "${certdir}/cert.pem"

  # Wait for hook script to clean the challenge and to deploy cert if used
  [[ -n "${HOOK}" ]] && ("${HOOK}" "deploy_cert" "${domain}" "${certdir}/privkey.pem" "${certdir}/cert.pem" "${certdir}/fullchain.pem" "${certdir}/chain.pem" "${timestamp}" || _exiterr 'deploy_cert hook returned with non-zero exit code')

  unset challenge_token
  echo " + Done!"
}
