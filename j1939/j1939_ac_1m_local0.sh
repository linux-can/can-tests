#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019 Oleksij Rempel <entwicklung@pengutronix.de>

set -e

CAN0=${1:-can0}
CAN1=${2:-can1}

echo "generate random data for the test"
dd if=/dev/urandom of=/tmp/test_1m bs=1M count=1

echo "start rx j1939acd and j1939cat on ${CAN0}"
j1939acd -r 100,80-120 -c /tmp/11223344.j1939acd 11223344 ${CAN0} &
PID_JACD0=$!
echo $PID_JACD0
sleep 2
j1939cat ${CAN0}:,,0x11223344 -r > /tmp/blup &
PID_JCAT0=$!
echo $PID_JCAT0

echo "start tx j1939acd and j1939cat on ${CAN0}"
j1939acd -r 100,80-120 -c /tmp/11223340.j1939acd 11223340 ${CAN0} &
PID_JACD1=$!
sleep 2
j1939cat -i /tmp/test_1m ${CAN0}:,,0x11223340 :,,0x11223344
sleep 2

echo "kill all users on ${CAN0}"
kill $PID_JACD0
kill $PID_JCAT0
kill $PID_JACD1

cmp /tmp/test_1m /tmp/blup

exit $?
