#!/bin/bash

# Usage: --revoke (-r) path/to/cert.pem
# Description: Revoke specified certificate
command_revoke() {
  init_system

  [[ -n "${CA_REVOKE_CERT}" ]] || _exiterr "Certificate authority doesn't allow certificate revocation."

  cert="${1}"
  if [[ -L "${cert}" ]]; then
    # follow symlink and use real certificate name (so we move the real file and not the symlink at the end)
    local link_target
    link_target="$(readlink -n "${cert}")"
    if [[ "${link_target}" =~ ^/ ]]; then
      cert="${link_target}"
    else
      cert="$(dirname "${cert}")/${link_target}"
    fi
  fi
  [[ -f "${cert}" ]] || _exiterr "Could not find certificate ${cert}"

  echo "Revoking ${cert}"

  cert64="$("${OPENSSL}" x509 -in "${cert}" -inform PEM -outform DER | urlbase64)"
  if [[ ${API} -eq 1 ]]; then
    response="$(signed_request "${CA_REVOKE_CERT}" '{"resource": "revoke-cert", "certificate": "'"${cert64}"'"}' | clean_json)"
  else
    response="$(signed_request "${CA_REVOKE_CERT}" '{"certificate": "'"${cert64}"'"}' | clean_json)"
  fi
  # if there is a problem with our revoke request _request (via signed_request) will report this and "exit 1" out
  # so if we are here, it is safe to assume the request was successful
  echo " + Done."
  echo " + Renaming certificate to ${cert}-revoked"
  mv -f "${cert}" "${cert}-revoked"
}
