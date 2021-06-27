#!/bin/bash

# Usage: --env (-e)
# Description: Output configuration variables for use in other scripts
command_env() {
  echo "# dehydrated configuration"
  load_config
  typeset -p CA CERTDIR ALPNCERTDIR CHALLENGETYPE DOMAINS_D DOMAINS_TXT HOOK HOOK_CHAIN RENEW_DAYS ACCOUNT_KEY ACCOUNT_KEY_JSON ACCOUNT_ID_JSON KEYSIZE WELLKNOWN PRIVATE_KEY_RENEW OPENSSL_CNF CONTACT_EMAIL LOCKFILE
}
