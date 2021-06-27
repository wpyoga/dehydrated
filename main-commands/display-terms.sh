#!/bin/sh

# Usage: --display-terms
# Description: Display current terms of service
command_terms() {
  init_system
  echo "The current terms of service: $CA_TERMS"
  echo "+ Done!"
  exit 0
}
