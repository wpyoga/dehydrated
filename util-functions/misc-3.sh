# Different sed version for different os types...
_sed() {
  if [[ "${OSTYPE}" = "Linux" || "${OSTYPE:0:5}" = "MINGW" ]]; then
    sed -r "${@}"
  else
    sed -E "${@}"
  fi
}

# Print error message and exit with error
_exiterr() {
  if [ -n "${1:-}" ]; then
    echo "ERROR: ${1}" >&2
  fi
  [[ "${skip_exit_hook:-no}" = "no" ]] && [[ -n "${HOOK:-}" ]] && ("${HOOK}" "exit_hook" "${1:-}" || echo 'exit_hook returned with non-zero exit code!' >&2)
  exit 1
}

# Remove newlines and whitespace from json
clean_json() {
  tr -d '\r\n' | _sed -e 's/ +/ /g' -e 's/\{ /{/g' -e 's/ \}/}/g' -e 's/\[ /[/g' -e 's/ \]/]/g'
}

# Encode data as url-safe formatted base64
urlbase64() {
  # urlbase64: base64 encoded string with '+' replaced with '-' and '/' replaced with '_'
  "${OPENSSL}" base64 -e | tr -d '\n\r' | _sed -e 's:=*$::g' -e 'y:+/:-_:'
}

# Decode data from url-safe formatted base64
deurlbase64() {
  data="$(cat | tr -d ' \n\r')"
  modlen=$((${#data} % 4))
  padding=""
  if [[ "${modlen}" = "2" ]]; then padding="==";
  elif [[ "${modlen}" = "3" ]]; then padding="="; fi
  printf "%s%s" "${data}" "${padding}" | tr -d '\n\r' | _sed -e 'y:-_:+/:' | "${OPENSSL}" base64 -d -A
}

# Convert hex string to binary data
hex2bin() {
  # Remove spaces, add leading zero, escape as hex string and parse with printf
  printf -- "$(cat | _sed -e 's/[[:space:]]//g' -e 's/^(.(.{2})*)$/0\1/' -e 's/(.{2})/\\x\1/g')"
}

# Convert binary data to hex string
bin2hex() {
  hexdump -e '16/1 "%02x"'
}

# OpenSSL writes to stderr/stdout even when there are no errors. So just
# display the output if the exit code was != 0 to simplify debugging.
_openssl() {
  set +e
  out="$("${OPENSSL}" "${@}" 2>&1)"
  res=$?
  set -e
  if [[ ${res} -ne 0 ]]; then
    echo "  + ERROR: failed to run $* (Exitcode: ${res})" >&2
    echo >&2
    echo "Details:" >&2
    echo "${out}" >&2
    echo >&2
    exit "${res}"
  fi
}
