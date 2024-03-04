#!/bin/bash

INTERFACE="$1"

if [ -n "$(iw dev |grep 'type managed')" ];then
    echo "this is managed";
    exit;
fi

if [ -n "$(iw dev |grep 'type monitor')" ];then
    echo "this is monitor";
    exit;
fi

#TODO
# sudo ip link set INTERFACE down
# sudo iw INTERFACE set monitor control
# sudo ip link set INTERFACE up


# sudo ip link set INTERFACE down
# sudo iw INTERFACE set type managed
# sudo ip link set INTERFACE up
