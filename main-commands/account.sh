#!/bin/bash

# Usage: --account
# Description: Update account contact information
command_account() {
  init_system
  FAILED=false

  NEW_ACCOUNT_KEY_JSON="$(_mktemp)"

  # Check if we have the registration url
  if [[ -z "${ACCOUNT_URL}" ]]; then
    _exiterr "Error retrieving registration url."
  fi

  echo "+ Updating registration url: ${ACCOUNT_URL} contact information..."
  if [[ ${API} -eq 1 ]]; then
    # If an email for the contact has been provided then adding it to the registered account
    if [[ -n "${CONTACT_EMAIL}" ]]; then
      (signed_request "${ACCOUNT_URL}" '{"resource": "reg", "contact":["mailto:'"${CONTACT_EMAIL}"'"]}' > "${NEW_ACCOUNT_KEY_JSON}") || FAILED=true
    else
      (signed_request "${ACCOUNT_URL}" '{"resource": "reg", "contact":[]}' > "${NEW_ACCOUNT_KEY_JSON}") || FAILED=true
    fi
  else
    # If an email for the contact has been provided then adding it to the registered account
    if [[ -n "${CONTACT_EMAIL}" ]]; then
      (signed_request "${ACCOUNT_URL}" '{"contact":["mailto:'"${CONTACT_EMAIL}"'"]}' > "${NEW_ACCOUNT_KEY_JSON}") || FAILED=true
    else
      (signed_request "${ACCOUNT_URL}" '{"contact":[]}' > "${NEW_ACCOUNT_KEY_JSON}") || FAILED=true
    fi
  fi

  if [[ "${FAILED}" = "true" ]]; then
    rm "${NEW_ACCOUNT_KEY_JSON}"
    _exiterr "Error updating account information. See message above for more information."
  fi
  if diff -q "${NEW_ACCOUNT_KEY_JSON}" "${ACCOUNT_KEY_JSON}" > /dev/null; then
    echo "+ Account information was the same after the update"
    rm "${NEW_ACCOUNT_KEY_JSON}"
  else
    ACCOUNT_KEY_JSON_BACKUP="${ACCOUNT_KEY_JSON%.*}-$(date +%s).json"
    echo "+ Backup ${ACCOUNT_KEY_JSON} as ${ACCOUNT_KEY_JSON_BACKUP}"
    cp -p "${ACCOUNT_KEY_JSON}" "${ACCOUNT_KEY_JSON_BACKUP}"
    echo "+ Populate ${ACCOUNT_KEY_JSON}"
    mv "${NEW_ACCOUNT_KEY_JSON}" "${ACCOUNT_KEY_JSON}"
  fi
  echo "+ Done!"
  exit 0
}
