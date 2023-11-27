#!/bin/sh

set -e

INTERFACE_1=$1
INTERFACE_2=$2

if [ "$#" -ne 2 ]; then
    echo "You must specify exactly two interfaces"
    exit
fi

ip link add br-firewall type bridge
ip link set $INTERFACE_1 master br-firewall
ip link set $INTERFACE_2 master br-firewall
ip link set br-firewall up

sleep infinity