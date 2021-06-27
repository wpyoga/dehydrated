# Create (identifiable) temporary files
_mktemp() {
  # shellcheck disable=SC2068
  mktemp ${@:-} "${TMPDIR:-/tmp}/dehydrated-XXXXXX"
}

# Check for script dependencies
check_dependencies() {
  # look for required binaries
  for binary in grep mktemp diff sed awk curl cut; do
    bin_path="$(command -v "${binary}" 2>/dev/null)" || _exiterr "This script requires ${binary}."
    [[ -x "${bin_path}" ]] || _exiterr "${binary} found in PATH but it's not executable"
  done

  # just execute some dummy and/or version commands to see if required tools are actually usable
  "${OPENSSL}" version > /dev/null 2>&1 || _exiterr "This script requires an openssl binary."
  _sed "" < /dev/null > /dev/null 2>&1 || _exiterr "This script requires sed with support for extended (modern) regular expressions."

  # curl returns with an error code in some ancient versions so we have to catch that
  set +e
  CURL_VERSION="$(curl -V 2>&1 | head -n1 | awk '{print $2}')"
  set -e
}
