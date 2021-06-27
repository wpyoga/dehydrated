#!/bin/bash

# Usage: --deactivate
# Description: Deactivate account
command_deactivate() {
  init_system

  echo "Deactivating account ${ACCOUNT_URL}"

  if [[ ${API} -eq 1 ]]; then
    echo "Deactivation for ACMEv1 is not implemented"
  else
    response="$(signed_request "${ACCOUNT_URL}" '{"status": "deactivated"}' | clean_json)"
    deactstatus=$(echo "$response" | jsonsh | get_json_string_value "status")
    if [[ "${deactstatus}" = "deactivated" ]]; then
      touch "${ACCOUNT_DEACTIVATED}"
    else
      _exiterr "Account deactivation failed!"
    fi
  fi

  echo " + Done."
}
