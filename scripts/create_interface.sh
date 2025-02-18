#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>"
  exit 1
fi

INTERFACE_NAME="$1"

if ! ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then
    sudo ip link add "$INTERFACE_NAME" type dummy
fi
