#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>"
  exit 1
fi

INTERFACE_NAME="$1"

sudo ip link set "$INTERFACE_NAME" up

if ! ip addr show "$INTERFACE_NAME" | grep -q "10.1.1.0/24"; then
    sudo ip addr add 10.1.1.0/24 dev "$INTERFACE_NAME"
fi