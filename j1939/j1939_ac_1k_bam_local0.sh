#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2020 Oleksij Rempel <entwicklung@pengutronix.de>

set -e

CAN0=${1:-can0}
CAN1=${2:-can1}

echo "generate random data for the test"
dd if=/dev/urandom of=/tmp/test_1k bs=1K count=1

j1939cat ${CAN0}:,0x12300 -B -r > /tmp/blup &
PID_JCAT0=$!
echo $PID_JCAT0

echo "start tx j1939acd and j1939cat on ${CAN0}"
j1939acd -r 100,80-120 -c /tmp/11223340.j1939acd 11223340 ${CAN0} &
PID_JACD1=$!
sleep 2
j1939cat -B -i /tmp/test_1k ${CAN0}:,,0x11223340 :,0x12300
sleep 2

echo "kill all users on ${CAN0}"
kill $PID_JCAT0
kill $PID_JACD1

cmp /tmp/test_1k /tmp/blup
exit $?
