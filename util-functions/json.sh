#!/bin/sh

# Generate json.sh path matching string
json_path() {
	if [ ! "${1}" = "-p" ]; then
		printf '"%s"' "${1}"
	else
		printf '%s' "${2}"
	fi
}

# Get string value from json dictionary
get_json_string_value() {
  local filter
  filter="$(printf 's/.*\[%s\][[:space:]]*"\([^"]*\)"/\\1/p' "$(json_path "${1:-}" "${2:-}")")"
  sed -n "${filter}"
}

# Get array values from json dictionary
get_json_array_values() {
  grep -E '^\['"$(json_path "${1:-}" "${2:-}")"',[0-9]*\]' | sed -e 's/\[[^\]*\][[:space:]]*//g' -e 's/^"//' -e 's/"$//'
}

# Get sub-dictionary from json
get_json_dict_value() {
  local filter
	echo "$(json_path "${1:-}" "${2:-}")"
  filter="$(printf 's/.*\[%s\][[:space:]]*\(.*\)/\\1/p' "$(json_path "${1:-}" "${2:-}")")"
  sed -n "${filter}" | jsonsh
}

# Get integer value from json
get_json_int_value() {
  local filter
  filter="$(printf 's/.*\[%s\][[:space:]]*\([^"]*\)/\\1/p' "$(json_path "${1:-}" "${2:-}")")"
  sed -n "${filter}"
}

# Get boolean value from json
get_json_bool_value() {
  local filter
  filter="$(printf 's/.*\[%s\][[:space:]]*\([^"]*\)/\\1/p' "$(json_path "${1:-}" "${2:-}")")"
  sed -n "${filter}"
}
