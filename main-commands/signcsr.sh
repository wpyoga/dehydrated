#!/bin/sh

# Usage: --signcsr (-s) path/to/csr.pem
# Description: Sign a given CSR, output CRT on stdout (advanced usage)
command_sign_csr() {
  init_system

  # redirect stdout to stderr
  # leave stdout over at fd 3 to output the cert
  exec 3>&1 1>&2

  # load csr
  csrfile="${1}"
  if [ ! -r "${csrfile}" ]; then
    _exiterr "Could not read certificate signing request ${csrfile}"
  fi
  csr="$(cat "${csrfile}")"

  # extract names
  altnames="$(extract_altnames "${csr}")"

  # gen cert
  certfile="$(_mktemp)"
  sign_csr "${csr}" ${altnames} 3> "${certfile}"

  # print cert
  echo "# CERT #" >&3
  cat "${certfile}" >&3
  echo >&3

  # print chain
  if [ -n "${PARAM_FULL_CHAIN:-}" ]; then
    # get and convert ca cert
    chainfile="$(_mktemp)"
    tmpchain="$(_mktemp)"
    http_request get "$("${OPENSSL}" x509 -in "${certfile}" -noout -text | grep 'CA Issuers - URI:' | cut -d':' -f2-)" > "${tmpchain}"
    if grep -q "BEGIN CERTIFICATE" "${tmpchain}"; then
      mv "${tmpchain}" "${chainfile}"
    else
      "${OPENSSL}" x509 -in "${tmpchain}" -inform DER -out "${chainfile}" -outform PEM
      rm "${tmpchain}"
    fi

    echo "# CHAIN #" >&3
    cat "${chainfile}" >&3

    rm "${chainfile}"
  fi

  # cleanup
  rm "${certfile}"

  exit 0
}
