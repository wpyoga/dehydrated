#!/bin/bash

# verify configuration values
verify_config() {
  [[ "${CHALLENGETYPE}" == "http-01" || "${CHALLENGETYPE}" == "dns-01" || "${CHALLENGETYPE}" == "tls-alpn-01" ]] || _exiterr "Unknown challenge type ${CHALLENGETYPE}... cannot continue."
  if [[ "${CHALLENGETYPE}" = "dns-01" ]] && [[ -z "${HOOK}" ]]; then
    _exiterr "Challenge type dns-01 needs a hook script for deployment... cannot continue."
  fi
  if [[ "${CHALLENGETYPE}" = "http-01" && ! -d "${WELLKNOWN}" && ! "${COMMAND:-}" = "register" ]]; then
    _exiterr "WELLKNOWN directory doesn't exist, please create ${WELLKNOWN} and set appropriate permissions."
  fi
  [[ "${KEY_ALGO}" == "rsa" || "${KEY_ALGO}" == "prime256v1" || "${KEY_ALGO}" == "secp384r1" ]] || _exiterr "Unknown public key algorithm ${KEY_ALGO}... cannot continue."
  if [[ -n "${IP_VERSION}" ]]; then
    [[ "${IP_VERSION}" = "4" || "${IP_VERSION}" = "6" ]] || _exiterr "Unknown IP version ${IP_VERSION}... cannot continue."
  fi
  [[ "${API}" == "auto" || "${API}" == "1" || "${API}" == "2" ]] || _exiterr "Unsupported API version defined in config: ${API}"
  [[ "${OCSP_DAYS}" =~ ^[0-9]+$ ]] || _exiterr "OCSP_DAYS must be a number"
}

# Setup default config values, search for and load configuration files
load_config() {
  # Check for config in various locations
  if [[ -z "${CONFIG:-}" ]]; then
    for check_config in "/etc/dehydrated" "/usr/local/etc/dehydrated" "${PWD}" "${SCRIPTDIR}"; do
      if [[ -f "${check_config}/config" ]]; then
        BASEDIR="${check_config}"
        CONFIG="${check_config}/config"
        break
      fi
    done
  fi

  # Preset
  CA_ZEROSSL="https://acme.zerossl.com/v2/DV90"
  CA_LETSENCRYPT="https://acme-v02.api.letsencrypt.org/directory"
  CA_LETSENCRYPT_TEST="https://acme-staging-v02.api.letsencrypt.org/directory"
  CA_BUYPASS="https://api.buypass.com/acme/directory"
  CA_BUYPASS_TEST="https://api.test4.buypass.no/acme/directory"

  # Default values
  CA="letsencrypt"
  OLDCA=
  CERTDIR=
  ALPNCERTDIR=
  ACCOUNTDIR=
  CHALLENGETYPE="http-01"
  CONFIG_D=
  CURL_OPTS=
  DOMAINS_D=
  DOMAINS_TXT=
  HOOK=
  PREFERRED_CHAIN=
  HOOK_CHAIN="no"
  RENEW_DAYS="30"
  KEYSIZE="4096"
  WELLKNOWN=
  PRIVATE_KEY_RENEW="yes"
  PRIVATE_KEY_ROLLOVER="no"
  KEY_ALGO=secp384r1
  OPENSSL=openssl
  OPENSSL_CNF=
  CONTACT_EMAIL=
  LOCKFILE=
  OCSP_MUST_STAPLE="no"
  OCSP_FETCH="no"
  OCSP_DAYS=5
  IP_VERSION=
  CHAINCACHE=
  AUTO_CLEANUP="no"
  DEHYDRATED_USER=
  DEHYDRATED_GROUP=
  API="auto"

  if [[ -z "${CONFIG:-}" ]]; then
    echo "#" >&2
    echo "# !! WARNING !! No main config file found, using default config!" >&2
    echo "#" >&2
  elif [[ -f "${CONFIG}" ]]; then
    echo "# INFO: Using main config file ${CONFIG}"
    BASEDIR="$(dirname "${CONFIG}")"
    # shellcheck disable=SC1090
    . "${CONFIG}"
  else
    _exiterr "Specified config file doesn't exist."
  fi

  if [[ -n "${CONFIG_D}" ]]; then
    if [[ ! -d "${CONFIG_D}" ]]; then
      _exiterr "The path ${CONFIG_D} specified for CONFIG_D does not point to a directory."
    fi

    # Allow globbing
    [[ -n "${ZSH_VERSION:-}" ]] && set +o noglob || set +f

    for check_config_d in "${CONFIG_D}"/*.sh; do
      if [[ -f "${check_config_d}" ]] && [[ -r "${check_config_d}" ]]; then
        echo "# INFO: Using additional config file ${check_config_d}"
        # shellcheck disable=SC1090
        . "${check_config_d}"
      else
        _exiterr "Specified additional config ${check_config_d} is not readable or not a file at all."
      fi
    done

    # Disable globbing
    [[ -n "${ZSH_VERSION:-}" ]] && set -o noglob || set -f
  fi

  # Check for missing dependencies
  check_dependencies

  has_sudo() {
    command -v sudo > /dev/null 2>&1 || _exiterr "DEHYDRATED_USER set but sudo not available. Please install sudo."
  }

  # Check if we are running & are allowed to run as root
  if [[ -n "$DEHYDRATED_USER" ]]; then
    command -v getent > /dev/null 2>&1 || _exiterr "DEHYDRATED_USER set but getent not available. Please install getent."

    TARGET_UID="$(getent passwd "${DEHYDRATED_USER}" | cut -d':' -f3)" || _exiterr "DEHYDRATED_USER ${DEHYDRATED_USER} is invalid"
    if [[ -z "${DEHYDRATED_GROUP}" ]]; then
      if [[ "${EUID}" != "${TARGET_UID}" ]]; then
        echo "# INFO: Running $0 as ${DEHYDRATED_USER}"
        has_sudo && exec sudo -u "${DEHYDRATED_USER}" "${0}" "${ORIGARGS[@]}"
      fi
    else
      TARGET_GID="$(getent group "${DEHYDRATED_GROUP}" | cut -d':' -f3)" || _exiterr "DEHYDRATED_GROUP ${DEHYDRATED_GROUP} is invalid"
      if [[ -z "${EGID:-}" ]]; then
        command -v id > /dev/null 2>&1 || _exiterr "DEHYDRATED_GROUP set, don't know current gid and 'id' not available... Please provide 'id' binary."
        EGID="$(id -g)"
      fi
      if [[ "${EUID}" != "${TARGET_UID}" ]] || [[ "${EGID}" != "${TARGET_GID}" ]]; then
        echo "# INFO: Running $0 as ${DEHYDRATED_USER}/${DEHYDRATED_GROUP}"
        has_sudo && exec sudo -u "${DEHYDRATED_USER}" -g "${DEHYDRATED_GROUP}" "${0}" "${ORIGARGS[@]}"
      fi
    fi
  elif [[ -n "${DEHYDRATED_GROUP}" ]]; then
    _exiterr "DEHYDRATED_GROUP can only be used in combination with DEHYDRATED_USER."
  fi

  # Remove slash from end of BASEDIR. Mostly for cleaner outputs, doesn't change functionality.
  [[ "$BASEDIR" != "/" ]] && BASEDIR="${BASEDIR%%/}"

  # Check BASEDIR and set default variables
  [[ -d "${BASEDIR}" ]] || _exiterr "BASEDIR does not exist: ${BASEDIR}"

  # Check for ca cli parameter
  if [ -n "${PARAM_CA:-}" ]; then
    CA="${PARAM_CA}"
  fi

  # Preset CAs
  if [ "${CA}" = "letsencrypt" ]; then
    CA="${CA_LETSENCRYPT}"
  elif [ "${CA}" = "letsencrypt-test" ]; then
    CA="${CA_LETSENCRYPT_TEST}"
  elif [ "${CA}" = "zerossl" ]; then
    CA="${CA_ZEROSSL}"
  elif [ "${CA}" = "buypass" ]; then
    CA="${CA_BUYPASS}"
  elif [ "${CA}" = "buypass-test" ]; then
    CA="${CA_BUYPASS_TEST}"
  fi

  if [[ -z "${OLDCA}" ]] && [[ "${CA}" = "https://acme-v02.api.letsencrypt.org/directory" ]]; then
    OLDCA="https://acme-v01.api.letsencrypt.org/directory"
  fi

  # Create new account directory or symlink to account directory from old CA
  # dev note: keep in mind that because of the use of 'echo' instead of 'printf' or
  # similar there is a newline encoded in the directory name. not going to fix this
  # since it's a non-issue and trying to fix existing installations would be too much
  # trouble
  CAHASH="$(echo "${CA}" | urlbase64)"
  [[ -z "${ACCOUNTDIR}" ]] && ACCOUNTDIR="${BASEDIR}/accounts"
  if [[ ! -e "${ACCOUNTDIR}/${CAHASH}" ]]; then
    OLDCAHASH="$(echo "${OLDCA}" | urlbase64)"
    mkdir -p "${ACCOUNTDIR}"
    if [[ -n "${OLDCA}" ]] && [[ -e "${ACCOUNTDIR}/${OLDCAHASH}" ]]; then
      echo "! Reusing account from ${OLDCA}"
      ln -s "${OLDCAHASH}" "${ACCOUNTDIR}/${CAHASH}"
    else
      mkdir "${ACCOUNTDIR}/${CAHASH}"
    fi
  fi

  [[ -f "${ACCOUNTDIR}/${CAHASH}/config" ]] && . "${ACCOUNTDIR}/${CAHASH}/config"
  ACCOUNT_KEY="${ACCOUNTDIR}/${CAHASH}/account_key.pem"
  ACCOUNT_KEY_JSON="${ACCOUNTDIR}/${CAHASH}/registration_info.json"
  ACCOUNT_ID_JSON="${ACCOUNTDIR}/${CAHASH}/account_id.json"
  ACCOUNT_DEACTIVATED="${ACCOUNTDIR}/${CAHASH}/deactivated"

  if [[ -f "${ACCOUNT_DEACTIVATED}" ]]; then
    _exiterr "Account has been deactivated. Remove account and create a new one using --register."
  fi

  if [[ -f "${BASEDIR}/private_key.pem" ]] && [[ ! -f "${ACCOUNT_KEY}" ]]; then
    echo "! Moving private_key.pem to ${ACCOUNT_KEY}"
    mv "${BASEDIR}/private_key.pem" "${ACCOUNT_KEY}"
  fi
  if [[ -f "${BASEDIR}/private_key.json" ]] && [[ ! -f "${ACCOUNT_KEY_JSON}" ]]; then
    echo "! Moving private_key.json to ${ACCOUNT_KEY_JSON}"
    mv "${BASEDIR}/private_key.json" "${ACCOUNT_KEY_JSON}"
  fi

  [[ -z "${CERTDIR}" ]] && CERTDIR="${BASEDIR}/certs"
  [[ -z "${ALPNCERTDIR}" ]] && ALPNCERTDIR="${BASEDIR}/alpn-certs"
  [[ -z "${CHAINCACHE}" ]] && CHAINCACHE="${BASEDIR}/chains"
  [[ -z "${DOMAINS_TXT}" ]] && DOMAINS_TXT="${BASEDIR}/domains.txt"
  [[ -z "${WELLKNOWN}" ]] && WELLKNOWN="/var/www/dehydrated"
  [[ -z "${LOCKFILE}" ]] && LOCKFILE="${BASEDIR}/lock"
  [[ -z "${OPENSSL_CNF}" ]] && OPENSSL_CNF="$("${OPENSSL}" version -d | cut -d\" -f2)/openssl.cnf"
  [[ -n "${PARAM_LOCKFILE_SUFFIX:-}" ]] && LOCKFILE="${LOCKFILE}-${PARAM_LOCKFILE_SUFFIX}"
  [[ -n "${PARAM_NO_LOCK:-}" ]] && LOCKFILE=""

  [[ -n "${PARAM_HOOK:-}" ]] && HOOK="${PARAM_HOOK}"
  [[ -n "${PARAM_DOMAINS_TXT:-}" ]] && DOMAINS_TXT="${PARAM_DOMAINS_TXT}"
  [[ -n "${PARAM_PREFERRED_CHAIN:-}" ]] && PREFERRED_CHAIN="${PARAM_PREFERRED_CHAIN}"
  [[ -n "${PARAM_CERTDIR:-}" ]] && CERTDIR="${PARAM_CERTDIR}"
  [[ -n "${PARAM_ALPNCERTDIR:-}" ]] && ALPNCERTDIR="${PARAM_ALPNCERTDIR}"
  [[ -n "${PARAM_CHALLENGETYPE:-}" ]] && CHALLENGETYPE="${PARAM_CHALLENGETYPE}"
  [[ -n "${PARAM_KEY_ALGO:-}" ]] && KEY_ALGO="${PARAM_KEY_ALGO}"
  [[ -n "${PARAM_OCSP_MUST_STAPLE:-}" ]] && OCSP_MUST_STAPLE="${PARAM_OCSP_MUST_STAPLE}"
  [[ -n "${PARAM_IP_VERSION:-}" ]] && IP_VERSION="${PARAM_IP_VERSION}"

  if [ "${PARAM_FORCE_VALIDATION:-no}" = "yes" ] && [ "${PARAM_FORCE:-no}" = "no" ]; then
    _exiterr "Argument --force-validation can only be used in combination with --force (-x)"
  fi

  if [ ! "${1:-}" = "noverify" ]; then
    verify_config
  fi
  store_configvars
}
