#!/bin/sh
#
# testscript to check CAN filters and CAN frame flow in Linux network layer
#
# $Id$
#

if [ $(id -ru) -ne 0 ]; then
     echo You need to be root to execute these tests
     exit 1
fi

# load needed CAN networklayer modules
modprobe -f can
modprobe -f can_raw

# ensure the vcan driver to perform the ECHO on driver level
modprobe -r vcan
modprobe -f vcan echo=1

VCAN=vcan0

# create virtual CAN device
ip link add dev $VCAN type vcan || exit 1
ifconfig $VCAN up

# check precondition for CAN frame flow test
HAS_ECHO=`ip link show $VCAN | grep -c ECHO`

if [ $HAS_ECHO -ne 1 ]
then
    return 1
fi

# test of CAN filters on af_can.c 
./tst-filter $VCAN || return 1

# test of CAN frame flow down to the netdevice and up again
./tst-rcv-own-msgs $VCAN || return 1

echo ---
echo "CAN networklayer tests succeeded."
echo ---

return 0


