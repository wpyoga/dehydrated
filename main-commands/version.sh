#!/bin/bash

# Usage: --version (-v)
# Description: Print version information
command_version() {
  load_config noverify

  echo "Dehydrated by Lukas Schauer"
  echo "https://dehydrated.io"
  echo ""
  echo "Dehydrated version: ${VERSION}"
  revision="$(cd "${SCRIPTDIR}"; git rev-parse HEAD 2>/dev/null || echo "unknown")"
  echo "GIT-Revision: ${revision}"
  echo ""
  if [[ "${OSTYPE}" =~ "BSD" ]]; then
    echo "OS: $(uname -sr)"
  elif [[ -e /etc/os-release ]]; then
    ( . /etc/os-release && echo "OS: $PRETTY_NAME" )
  elif [[ -e /usr/lib/os-release ]]; then
    ( . /usr/lib/os-release && echo "OS: $PRETTY_NAME" )
  else
    echo "OS: $(cat /etc/issue | grep -v ^$ | head -n1 | _sed 's/\\(r|n|l) .*//g')"
  fi
  echo "Used software:"
  [[ -n "${BASH_VERSION:-}" ]] && echo " bash: ${BASH_VERSION}"
  [[ -n "${ZSH_VERSION:-}" ]] && echo " zsh: ${ZSH_VERSION}"
  echo " curl: ${CURL_VERSION}"
  if [[ "${OSTYPE}" =~ "BSD" ]]; then
    echo " awk, sed, mktemp, grep, diff: BSD base system versions"
  else
    echo " awk: $(awk -W version 2>&1 | head -n1)"
    echo " sed: $(sed --version 2>&1 | head -n1)"
    echo " mktemp: $(mktemp --version 2>&1 | head -n1)"
    echo " grep: $(grep --version 2>&1 | head -n1)"
    echo " diff: $(diff --version 2>&1 | head -n1)"
  fi
  echo " openssl: $("${OPENSSL}" version 2>&1)"

  exit 0
}
