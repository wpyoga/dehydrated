#!/bin/bash

# Send http(s) request with specified method
http_request() {
  tempcont="$(_mktemp)"
  tempheaders="$(_mktemp)"

  if [[ -n "${IP_VERSION:-}" ]]; then
      ip_version="-${IP_VERSION}"
  fi

  set +e
  if [[ "${1}" = "head" ]]; then
    statuscode="$(curl ${ip_version:-} ${CURL_OPTS} -A "dehydrated/${VERSION} curl/${CURL_VERSION}" -s -w "%{http_code}" -o "${tempcont}" "${2}" -I)"
    curlret="${?}"
    touch "${tempheaders}"
  elif [[ "${1}" = "get" ]]; then
    statuscode="$(curl ${ip_version:-} ${CURL_OPTS} -A "dehydrated/${VERSION} curl/${CURL_VERSION}" -L -s -w "%{http_code}" -o "${tempcont}" -D "${tempheaders}" "${2}")"
    curlret="${?}"
  elif [[ "${1}" = "post" ]]; then
    statuscode="$(curl ${ip_version:-} ${CURL_OPTS} -A "dehydrated/${VERSION} curl/${CURL_VERSION}" -s -w "%{http_code}" -o "${tempcont}" "${2}" -D "${tempheaders}" -H 'Content-Type: application/jose+json' -d "${3}")"
    curlret="${?}"
  else
    set -e
    _exiterr "Unknown request method: ${1}"
  fi
  set -e

  if [[ ! "${curlret}" = "0" ]]; then
    _exiterr "Problem connecting to server (${1} for ${2}; curl returned with ${curlret})"
  fi

  if [[ ! "${statuscode:0:1}" = "2" ]]; then
    # check for existing registration warning
    if [[ "${API}" = "1" ]] && [[ -n "${CA_NEW_REG:-}" ]] && [[ "${2}" = "${CA_NEW_REG:-}" ]] && [[ "${statuscode}" = "409" ]] && grep -q "Registration key is already in use" "${tempcont}"; then
      # do nothing
      :
    # check for already-revoked warning
    elif [[ -n "${CA_REVOKE_CERT:-}" ]] && [[ "${2}" = "${CA_REVOKE_CERT:-}" ]] && [[ "${statuscode}" = "409" ]]; then
      grep -q "Certificate already revoked" "${tempcont}" && return
    else
      echo "  + ERROR: An error occurred while sending ${1}-request to ${2} (Status ${statuscode})" >&2
      echo >&2
      echo "Details:" >&2
      cat "${tempheaders}" >&2
      cat "${tempcont}" >&2
      echo >&2
      echo >&2

      # An exclusive hook for the {1}-request error might be useful (e.g., for sending an e-mail to admins)
      if [[ -n "${HOOK}" ]]; then
        errtxt="$(cat ${tempcont})"
        errheaders="$(cat ${tempheaders})"
        "${HOOK}" "request_failure" "${statuscode}" "${errtxt}" "${1}" "${errheaders}" || _exiterr 'request_failure hook returned with non-zero exit code'
      fi

      rm -f "${tempcont}"
      rm -f "${tempheaders}"

      # remove temporary domains.txt file if used
      [[ "${COMMAND:-}" = "sign_domains" && -n "${PARAM_DOMAIN:-}" && -n "${DOMAINS_TXT:-}" ]] && rm "${DOMAINS_TXT}"
      _exiterr
    fi
  fi

  if { true >&4; } 2>/dev/null; then
    cat "${tempheaders}" >&4
  fi
  cat "${tempcont}"
  rm -f "${tempcont}"
  rm -f "${tempheaders}"
}

# Send signed request
signed_request() {
  # Encode payload as urlbase64
  payload64="$(printf '%s' "${2}" | urlbase64)"

  # Retrieve nonce from acme-server
  if [[ ${API} -eq 1 ]]; then
    nonce="$(http_request head "${CA}" | grep -i ^Replay-Nonce: | cut -d':' -f2- | tr -d ' \t\n\r')"
  else
    nonce="$(http_request head "${CA_NEW_NONCE}" | grep -i ^Replay-Nonce: | cut -d':' -f2- | tr -d ' \t\n\r')"
  fi

  # Build header with just our public key and algorithm information
  header='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}}'

  if [[ ${API} -eq 1 ]]; then
    # Build another header which also contains the previously received nonce and encode it as urlbase64
    protected='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}, "nonce": "'"${nonce}"'"}'
    protected64="$(printf '%s' "${protected}" | urlbase64)"
  else
    # Build another header which also contains the previously received nonce and url and encode it as urlbase64
    if [[ -n "${ACCOUNT_URL:-}" ]]; then
      protected='{"alg": "RS256", "kid": "'"${ACCOUNT_URL}"'", "url": "'"${1}"'", "nonce": "'"${nonce}"'"}'
    else
      protected='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}, "url": "'"${1}"'", "nonce": "'"${nonce}"'"}'
    fi
    protected64="$(printf '%s' "${protected}" | urlbase64)"
  fi

  # Sign header with nonce and our payload with our private key and encode signature as urlbase64
  signed64="$(printf '%s' "${protected64}.${payload64}" | "${OPENSSL}" dgst -sha256 -sign "${ACCOUNT_KEY}" | urlbase64)"

  if [[ ${API} -eq 1 ]]; then
    # Send header + extended header + payload + signature to the acme-server
    data='{"header": '"${header}"', "protected": "'"${protected64}"'", "payload": "'"${payload64}"'", "signature": "'"${signed64}"'"}'
  else
    # Send extended header + payload + signature to the acme-server
    data='{"protected": "'"${protected64}"'", "payload": "'"${payload64}"'", "signature": "'"${signed64}"'"}'
  fi

  http_request post "${1}" "${data}"
}
