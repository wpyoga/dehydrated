#!/bin/bash

# Main method (parses script arguments and calls command_* methods)
main() {
  exit_with_errorcode=0
  skip_exit_hook=no
  COMMAND=""
  set_command() {
    [[ -z "${COMMAND}" ]] || _exiterr "Only one command can be executed at a time. See help (-h) for more information."
    COMMAND="${1}"
  }

  check_parameters() {
    if [[ -z "${1:-}" ]]; then
      echo "The specified command requires additional parameters. See help:" >&2
      echo >&2
      command_help >&2
      exit 1
    elif [[ "${1:0:1}" = "-" ]]; then
      _exiterr "Invalid argument: ${1}"
    fi
  }

  # shellcheck disable=SC2199
  [[ -z "${@}" ]] && eval set -- "--help"

  while (( ${#} )); do
    case "${1}" in
      --help|-h)
        command_help
        exit 0
        ;;

      --env|-e)
        set_command env
        ;;

      --cron|-c)
        set_command sign_domains
        ;;

      --register)
        set_command register
        ;;

      --account)
        set_command account
        ;;

      # PARAM_Usage: --accept-terms
      # PARAM_Description: Accept CAs terms of service
      --accept-terms)
        PARAM_ACCEPT_TERMS="yes"
        ;;

      --display-terms)
        set_command terms
        ;;

      --signcsr|-s)
        shift 1
        set_command sign_csr
        check_parameters "${1:-}"
        PARAM_CSR="${1}"
        ;;

      --revoke|-r)
        shift 1
        set_command revoke
        check_parameters "${1:-}"
        PARAM_REVOKECERT="${1}"
        ;;

      --deactivate)
        set_command deactivate
        ;;

      --version|-v)
        set_command version
        ;;

      --cleanup|-gc)
        set_command cleanup
        ;;

      --cleanup-delete|-gcd)
        set_command cleanupdelete
        PARAM_CLEANUPDELETE="yes"
        ;;

      # PARAM_Usage: --full-chain (-fc)
      # PARAM_Description: Print full chain when using --signcsr
      --full-chain|-fc)
        PARAM_FULL_CHAIN="1"
        ;;

      # PARAM_Usage: --ipv4 (-4)
      # PARAM_Description: Resolve names to IPv4 addresses only
      --ipv4|-4)
        PARAM_IP_VERSION="4"
        ;;

      # PARAM_Usage: --ipv6 (-6)
      # PARAM_Description: Resolve names to IPv6 addresses only
      --ipv6|-6)
        PARAM_IP_VERSION="6"
        ;;

      # PARAM_Usage: --domain (-d) domain.tld
      # PARAM_Description: Use specified domain name(s) instead of domains.txt entry (one certificate!)
      --domain|-d)
        shift 1
        check_parameters "${1:-}"
        if [[ -z "${PARAM_DOMAIN:-}" ]]; then
          PARAM_DOMAIN="${1}"
        else
          PARAM_DOMAIN="${PARAM_DOMAIN} ${1}"
         fi
        ;;

      # PARAM_Usage: --ca url/preset
      # PARAM_Description: Use specified CA URL or preset
      --ca)
        shift 1
        check_parameters "${1:-}"
        [[ -n "${PARAM_CA:-}" ]] && _exiterr "CA can only be specified once!"
        PARAM_CA="${1}"
        ;;

      # PARAM_Usage: --alias certalias
      # PARAM_Description: Use specified name for certificate directory (and per-certificate config) instead of the primary domain (only used if --domain is specified)
      --alias)
        shift 1
        check_parameters "${1:-}"
        [[ -n "${PARAM_ALIAS:-}" ]] && _exiterr "Alias can only be specified once!"
        PARAM_ALIAS="${1}"
        ;;

      # PARAM_Usage: --keep-going (-g)
      # PARAM_Description: Keep going after encountering an error while creating/renewing multiple certificates in cron mode
      --keep-going|-g)
        PARAM_KEEP_GOING="yes"
        ;;

      # PARAM_Usage: --force (-x)
      # PARAM_Description: Force renew of certificate even if it is longer valid than value in RENEW_DAYS
      --force|-x)
        PARAM_FORCE="yes"
        ;;

      # PARAM_Usage: --force-validation
      # PARAM_Description: Force revalidation of domain names (used in combination with --force)
      --force-validation)
        PARAM_FORCE_VALIDATION="yes"
        ;;

      # PARAM_Usage: --no-lock (-n)
      # PARAM_Description: Don't use lockfile (potentially dangerous!)
      --no-lock|-n)
        PARAM_NO_LOCK="yes"
        ;;

      # PARAM_Usage: --lock-suffix example.com
      # PARAM_Description: Suffix lockfile name with a string (useful for with -d)
      --lock-suffix)
        shift 1
        check_parameters "${1:-}"
        PARAM_LOCKFILE_SUFFIX="${1}"
        ;;

      # PARAM_Usage: --ocsp
      # PARAM_Description: Sets option in CSR indicating OCSP stapling to be mandatory
      --ocsp)
        PARAM_OCSP_MUST_STAPLE="yes"
        ;;

      # PARAM_Usage: --privkey (-p) path/to/key.pem
      # PARAM_Description: Use specified private key instead of account key (useful for revocation)
      --privkey|-p)
        shift 1
        check_parameters "${1:-}"
        PARAM_ACCOUNT_KEY="${1}"
        ;;

      # PARAM_Usage: --domains-txt path/to/domains.txt
      # PARAM_Description: Use specified domains.txt instead of default/configured one
      --domains-txt)
        shift 1
        check_parameters "${1:-}"
        PARAM_DOMAINS_TXT="${1}"
        ;;

      # PARAM_Usage: --config (-f) path/to/config
      # PARAM_Description: Use specified config file
      --config|-f)
        shift 1
        check_parameters "${1:-}"
        CONFIG="${1}"
        ;;

      # PARAM_Usage: --hook (-k) path/to/hook.sh
      # PARAM_Description: Use specified script for hooks
      --hook|-k)
        shift 1
        check_parameters "${1:-}"
        PARAM_HOOK="${1}"
        ;;

      # PARAM_Usage: --preferred-chain issuer-cn
      # PARAM_Description: Use alternative certificate chain identified by issuer CN
      --preferred-chain)
        shift 1
        check_parameters "${1:-}"
        PARAM_PREFERRED_CHAIN="${1}"
        ;;

      # PARAM_Usage: --out (-o) certs/directory
      # PARAM_Description: Output certificates into the specified directory
      --out|-o)
        shift 1
        check_parameters "${1:-}"
        PARAM_CERTDIR="${1}"
        ;;

      # PARAM_Usage: --alpn alpn-certs/directory
      # PARAM_Description: Output alpn verification certificates into the specified directory
      --alpn)
        shift 1
        check_parameters "${1:-}"
        PARAM_ALPNCERTDIR="${1}"
        ;;

      # PARAM_Usage: --challenge (-t) http-01|dns-01|tls-alpn-01
      # PARAM_Description: Which challenge should be used? Currently http-01, dns-01, and tls-alpn-01 are supported
      --challenge|-t)
        shift 1
        check_parameters "${1:-}"
        PARAM_CHALLENGETYPE="${1}"
        ;;

      # PARAM_Usage: --algo (-a) rsa|prime256v1|secp384r1
      # PARAM_Description: Which public key algorithm should be used? Supported: rsa, prime256v1 and secp384r1
      --algo|-a)
        shift 1
        check_parameters "${1:-}"
        PARAM_KEY_ALGO="${1}"
        ;;
      *)
        echo "Unknown parameter detected: ${1}" >&2
        echo >&2
        command_help >&2
        exit 1
        ;;
    esac

    shift 1
  done

  case "${COMMAND}" in
    env) command_env;;
    sign_domains) command_sign_domains;;
    register) command_register;;
    account) command_account;;
    sign_csr) command_sign_csr "${PARAM_CSR}";;
    revoke) command_revoke "${PARAM_REVOKECERT}";;
    deactivate) command_deactivate;;
    cleanup) command_cleanup;;
    terms) command_terms;;
    cleanupdelete) command_cleanupdelete;;
    version) command_version;;
    *) command_help; exit 1;;
  esac

  exit "${exit_with_errorcode}"
}
