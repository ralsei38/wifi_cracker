#!/bin/bash

INTERFACE="$1"

if [ -n "$(iw dev |grep 'type managed')" ];then
    sudo ip link set INTERFACE down
    sudo iw INTERFACE set monitor control
    sudo ip link set INTERFACE up
    echo "$1 was set to monitor mode."
    exit;
fi

if [ -n "$(iw dev |grep 'type monitor')" ];then
    sudo ip link set INTERFACE down
    sudo iw INTERFACE set type managed
    sudo ip link set INTERFACE up
    echo "$1 was set to managed mode."
    exit;
fi