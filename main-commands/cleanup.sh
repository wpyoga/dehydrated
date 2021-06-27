#!/bin/bash

# Usage: --cleanup (-gc)
# Description: Move unused certificate files to archive directory
command_cleanup() {
  if [ ! "${1:-}" = "noinit" ]; then
    load_config
  fi

  if [[ ! "${PARAM_CLEANUPDELETE:-}" = "yes" ]]; then
    # Create global archive directory if not existent
    if [[ ! -e "${BASEDIR}/archive" ]]; then
      mkdir "${BASEDIR}/archive"
    fi
  fi

  # Allow globbing
  [[ -n "${ZSH_VERSION:-}" ]] && set +o noglob || set +f

  # Loop over all certificate directories
  for certdir in "${CERTDIR}/"*; do
    # Skip if entry is not a folder
    [[ -d "${certdir}" ]] || continue

    # Get certificate name
    certname="$(basename "${certdir}")"

    # Create certificates archive directory if not existent
    if [[ ! "${PARAM_CLEANUPDELETE:-}" = "yes" ]]; then
      archivedir="${BASEDIR}/archive/${certname}"
      if [[ ! -e "${archivedir}" ]]; then
        mkdir "${archivedir}"
      fi
    fi

    # Loop over file-types (certificates, keys, signing-requests, ...)
    for filetype in cert.csr cert.pem chain.pem fullchain.pem privkey.pem ocsp.der; do
      # Delete all if symlink is broken
      if [[ -r "${certdir}/${filetype}" ]]; then
        # Look up current file in use
        current="$(basename "$(readlink "${certdir}/${filetype}")")"
      else
        if [[ -h "${certdir}/${filetype}" ]]; then
          echo "Removing broken symlink: ${certdir}/${filetype}"
          rm -f "${certdir}/${filetype}"
        fi
        current=""
      fi

      # Split filetype into name and extension
      filebase="$(echo "${filetype}" | cut -d. -f1)"
      fileext="$(echo "${filetype}" | cut -d. -f2)"

      # Loop over all files of this type
      for file in "${certdir}/${filebase}-"*".${fileext}" "${certdir}/${filebase}-"*".${fileext}-revoked"; do
        # Check if current file is in use, if unused move to archive directory
        filename="$(basename "${file}")"
        if [[ ! "${filename}" = "${current}" ]] && [[ -f "${certdir}/${filename}" ]]; then
          echo "${filename}"
          if [[ "${PARAM_CLEANUPDELETE:-}" = "yes" ]]; then
            echo "Deleting unused file: ${certname}/${filename}"
            rm "${certdir}/${filename}"
          else
            echo "Moving unused file to archive directory: ${certname}/${filename}"
            mv "${certdir}/${filename}" "${archivedir}/${filename}"
          fi
        fi
      done
    done
  done

  exit "${exit_with_errorcode}"
}

# Usage: --cleanup-delete (-gcd)
# Description: Deletes (!) unused certificate files
command_cleanupdelete() {
  command_cleanup
}
