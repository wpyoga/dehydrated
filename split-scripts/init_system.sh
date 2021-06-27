#!/bin/bash

# Initialize system
init_system() {
  load_config

  # Lockfile handling (prevents concurrent access)
  if [[ -n "${LOCKFILE}" ]]; then
    LOCKDIR="$(dirname "${LOCKFILE}")"
    [[ -w "${LOCKDIR}" ]] || _exiterr "Directory ${LOCKDIR} for LOCKFILE ${LOCKFILE} is not writable, aborting."
    ( set -C; date > "${LOCKFILE}" ) 2>/dev/null || _exiterr "Lock file '${LOCKFILE}' present, aborting."
    remove_lock() { rm -f "${LOCKFILE}"; }
    trap 'remove_lock' EXIT
  fi

  # Get CA URLs
  CA_DIRECTORY="$(http_request get "${CA}" | jsonsh)"

  # Automatic discovery of API version
  if [[ "${API}" = "auto" ]]; then
    grep -q newOrder <<< "${CA_DIRECTORY}" && API=2 || API=1
  fi

  if [[ ${API} -eq 1 ]]; then
    # shellcheck disable=SC2015
    CA_NEW_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-cert)" &&
    CA_NEW_AUTHZ="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-authz)" &&
    CA_NEW_REG="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value new-reg)" &&
    CA_TERMS="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value terms-of-service)" &&
    CA_REQUIRES_EAB="false" &&
    CA_REVOKE_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value revoke-cert)" ||
    _exiterr "Problem retrieving ACME/CA-URLs, check if your configured CA points to the directory entrypoint."
    # Since reg URI is missing from directory we will assume it is the same as CA_NEW_REG without the new part
    CA_REG=${CA_NEW_REG/new-reg/reg}
  else
    # shellcheck disable=SC2015
    CA_NEW_ORDER="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value newOrder)" &&
    CA_NEW_NONCE="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value newNonce)" &&
    CA_NEW_ACCOUNT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value newAccount)" &&
    CA_TERMS="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value -p '"meta","termsOfService"')" &&
    CA_REQUIRES_EAB="$(printf "%s" "${CA_DIRECTORY}" | get_json_bool_value -p '"meta","externalAccountRequired"' || echo false)" &&
    CA_REVOKE_CERT="$(printf "%s" "${CA_DIRECTORY}" | get_json_string_value revokeCert)" ||
    _exiterr "Problem retrieving ACME/CA-URLs, check if your configured CA points to the directory entrypoint."
    # Since acct URI is missing from directory we will assume it is the same as CA_NEW_ACCOUNT without the new part
    CA_ACCOUNT=${CA_NEW_ACCOUNT/new-acct/acct}
  fi

  # Export some environment variables to be used in hook script
  export WELLKNOWN BASEDIR CERTDIR ALPNCERTDIR CONFIG COMMAND

  # Checking for private key ...
  register_new_key="no"
  generated="false"
  if [[ -n "${PARAM_ACCOUNT_KEY:-}" ]]; then
    # a private key was specified from the command line so use it for this run
    echo "Using private key ${PARAM_ACCOUNT_KEY} instead of account key"
    ACCOUNT_KEY="${PARAM_ACCOUNT_KEY}"
    ACCOUNT_KEY_JSON="${PARAM_ACCOUNT_KEY}.json"
    ACCOUNT_ID_JSON="${PARAM_ACCOUNT_KEY}_id.json"
    [ "${COMMAND:-}" = "register" ] && register_new_key="yes"
  else
    # Check if private account key exists, if it doesn't exist yet generate a new one (rsa key)
    if [[ ! -e "${ACCOUNT_KEY}" ]]; then
      if [[ ! "${PARAM_ACCEPT_TERMS:-}" = "yes" ]]; then
        printf '\n' >&2
        printf 'To use dehydrated with this certificate authority you have to agree to their terms of service which you can find here: %s\n\n' "${CA_TERMS}" >&2
        printf 'To accept these terms of service run `%s --register --accept-terms`.\n' "${0}" >&2
        exit 1
      fi

      echo "+ Generating account key..."
      generated="true"
      local tmp_account_key="$(_mktemp)"
      _openssl genrsa -out "${tmp_account_key}" "${KEYSIZE}"
      cat "${tmp_account_key}" > "${ACCOUNT_KEY}"
      rm "${tmp_account_key}"
      register_new_key="yes"
    fi
  fi
  "${OPENSSL}" rsa -in "${ACCOUNT_KEY}" -check 2>/dev/null > /dev/null || _exiterr "Account key is not valid, cannot continue."

  # Get public components from private key and calculate thumbprint
  pubExponent64="$(printf '%x' "$("${OPENSSL}" rsa -in "${ACCOUNT_KEY}" -noout -text | awk '/publicExponent/ {print $2}')" | hex2bin | urlbase64)"
  pubMod64="$("${OPENSSL}" rsa -in "${ACCOUNT_KEY}" -noout -modulus | cut -d'=' -f2 | hex2bin | urlbase64)"

  thumbprint="$(printf '{"e":"%s","kty":"RSA","n":"%s"}' "${pubExponent64}" "${pubMod64}" | "${OPENSSL}" dgst -sha256 -binary | urlbase64)"

  # If we generated a new private key in the step above we have to register it with the acme-server
  if [[ "${register_new_key}" = "yes" ]]; then
    echo "+ Registering account key with ACME server..."
    FAILED=false

    if [[ ${API} -eq 1 && -z "${CA_NEW_REG}" ]] || [[ ${API} -eq 2 && -z "${CA_NEW_ACCOUNT}" ]]; then
      echo "Certificate authority doesn't allow registrations."
      FAILED=true
    fi

    # ZeroSSL special sauce
    if [[ "${CA}" = "${CA_ZEROSSL}" ]]; then
      if [[ -z "${EAB_KID:-}" ]] ||  [[ -z "${EAB_HMAC_KEY:-}" ]]; then
        if [[ -z "${CONTACT_EMAIL}" ]]; then
          echo "ZeroSSL requires contact email to be set or EAB_KID/EAB_HMAC_KEY to be manually configured"
          FAILED=true
        else
          zeroapi="$(curl -s "https://api.zerossl.com/acme/eab-credentials-email" -d "email=${CONTACT_EMAIL}" | jsonsh)"
          EAB_KID="$(printf "%s" "${zeroapi}" | get_json_string_value eab_kid)"
          EAB_HMAC_KEY="$(printf "%s" "${zeroapi}" | get_json_string_value eab_hmac_key)"
          if [[ -z "${EAB_KID:-}" ]] ||  [[ -z "${EAB_HMAC_KEY:-}" ]]; then
            echo "Unknown error retrieving ZeroSSL API credentials"
            echo "${zeroapi}"
            FAILED=true
          fi
        fi
      fi
    fi

    # Check if external account is required
    if [[ "${FAILED}" = "false" ]]; then
      if [[ "${CA_REQUIRES_EAB}" = "true" ]]; then
        if [[ -z "${EAB_KID:-}" ]] || [[ -z "${EAB_HMAC_KEY:-}" ]]; then
          FAILED=true
          echo "This CA requires an external account but no EAB_KID/EAB_HMAC_KEY has been configured"
        fi
      fi
    fi

    # If an email for the contact has been provided then adding it to the registration request
    if [[ "${FAILED}" = "false" ]]; then
      if [[ ${API} -eq 1 ]]; then
        if [[ -n "${CONTACT_EMAIL}" ]]; then
          (signed_request "${CA_NEW_REG}" '{"resource": "new-reg", "contact":["mailto:'"${CONTACT_EMAIL}"'"], "agreement": "'"${CA_TERMS}"'"}' > "${ACCOUNT_KEY_JSON}") || FAILED=true
        else
          (signed_request "${CA_NEW_REG}" '{"resource": "new-reg", "agreement": "'"${CA_TERMS}"'"}' > "${ACCOUNT_KEY_JSON}") || FAILED=true
        fi
      else
        if [[ -n "${EAB_KID:-}" ]] && [[ -n "${EAB_HMAC_KEY:-}" ]]; then
          eab_url="${CA_NEW_ACCOUNT}"
          eab_protected64="$(printf '{"alg":"HS256","kid":"%s","url":"%s"}' "${EAB_KID}" "${eab_url}" | urlbase64)"
          eab_payload64="$(printf "%s" '{"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}' | urlbase64)"
          eab_key="$(printf "%s" "${EAB_HMAC_KEY}" | deurlbase64 | bin2hex)"
          eab_signed64="$(printf '%s' "${eab_protected64}.${eab_payload64}" | "${OPENSSL}" dgst -binary -sha256 -mac HMAC -macopt "hexkey:${eab_key}" | urlbase64)"

          if [[ -n "${CONTACT_EMAIL}" ]]; then
            regjson='{"contact":["mailto:'"${CONTACT_EMAIL}"'"], "termsOfServiceAgreed": true, "externalAccountBinding": {"protected": "'"${eab_protected64}"'", "payload": "'"${eab_payload64}"'", "signature": "'"${eab_signed64}"'"}}'
          else
            regjson='{"termsOfServiceAgreed": true, "externalAccountBinding": {"protected": "'"${eab_protected64}"'", "payload": "'"${eab_payload64}"'", "signature": "'"${eab_signed64}"'"}}'
          fi
        else
          if [[ -n "${CONTACT_EMAIL}" ]]; then
            regjson='{"contact":["mailto:'"${CONTACT_EMAIL}"'"], "termsOfServiceAgreed": true}'
          else
            regjson='{"termsOfServiceAgreed": true}'
          fi
        fi
        (signed_request "${CA_NEW_ACCOUNT}" "${regjson}" > "${ACCOUNT_KEY_JSON}") || FAILED=true
      fi
    fi

    if [[ "${FAILED}" = "true" ]]; then
      echo >&2
      echo >&2
      echo "Error registering account key. See message above for more information." >&2
      if [[ "${generated}" = "true" ]]; then
        rm "${ACCOUNT_KEY}"
      fi
      rm -f "${ACCOUNT_KEY_JSON}"
      exit 1
    fi
  elif [[ "${COMMAND:-}" = "register" ]]; then
    echo "+ Account already registered!"
    exit 0
  fi

  # Read account information or request from CA if missing
  if [[ -e "${ACCOUNT_KEY_JSON}" ]]; then
    if [[ ${API} -eq 1 ]]; then
      ACCOUNT_ID="$(cat "${ACCOUNT_KEY_JSON}" | jsonsh | get_json_int_value id)"
      ACCOUNT_URL="${CA_REG}/${ACCOUNT_ID}"
    else
      if [[ -e "${ACCOUNT_ID_JSON}" ]]; then
        ACCOUNT_URL="$(cat "${ACCOUNT_ID_JSON}" | jsonsh | get_json_string_value url)"
      fi
      # if account URL is not storred, fetch it from the CA
      if [[ -z "${ACCOUNT_URL:-}" ]]; then
        echo "+ Fetching account URL..."
        ACCOUNT_URL="$(signed_request "${CA_NEW_ACCOUNT}" '{"onlyReturnExisting": true}' 4>&1 | grep -i ^Location: | cut -d':' -f2- | tr -d ' \t\r\n')"
        if [[ -z "${ACCOUNT_URL}" ]]; then
          _exiterr "Unknown error on fetching account information"
        fi
        echo '{"url":"'"${ACCOUNT_URL}"'"}' > "${ACCOUNT_ID_JSON}" # store the URL for next time
      fi
    fi
  else
    echo "Fetching missing account information from CA..."
    if [[ ${API} -eq 1 ]]; then
      _exiterr "This is not implemented for ACMEv1! Consider switching to ACMEv2 :)"
    else
      ACCOUNT_URL="$(signed_request "${CA_NEW_ACCOUNT}" '{"onlyReturnExisting": true}' 4>&1 | grep -i ^Location: | cut -d':' -f2- | tr -d ' \t\r\n')"
      ACCOUNT_INFO="$(signed_request "${ACCOUNT_URL}" '{}')"
    fi
    echo "${ACCOUNT_INFO}" > "${ACCOUNT_KEY_JSON}"
  fi
}
