#!/bin/bash

if ! ip link show dummy0 > /dev/null 2>&1; then
    sudo ip link add dummy0 type dummy
fi

sudo ip link set dummy0 up

if ! ip addr show dummy0 | grep -q "10.1.1.0/24"; then
    sudo ip addr add 10.1.1.0/24 dev dummy0
fi