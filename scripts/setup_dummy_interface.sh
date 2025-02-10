#!/bin/bash

sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 10.1.1.0/24 dev dummy0