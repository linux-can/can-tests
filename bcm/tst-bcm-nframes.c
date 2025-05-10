/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * tst-bcm-nframes.c
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/bcm.h>

#define U64_DATA(p) (*(unsigned long long*)(p)->data)
#define NFRAMES 16
#define LOOPS 0x100

int main(int argc, char **argv)
{
	int s;
	struct sockaddr_can addr;
	int i, loops;

	static struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame[NFRAMES];
	} msg;

	s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (s < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = PF_CAN;
	addr.can_ifindex = if_nametoindex("vcan2");

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	for (loops = 1; loops < LOOPS; loops++) {

		/* vary the time to update the bcm operation */
		usleep(2900 + 9 * loops);

		/* set header values */
		msg.msg_head.opcode  = TX_SETUP;
		msg.msg_head.can_id  = 0x42;
		msg.msg_head.flags   = SETTIMER|STARTTIMER;
		msg.msg_head.nframes = NFRAMES;
		msg.msg_head.count = 8;
		msg.msg_head.ival1.tv_sec = 0;
		msg.msg_head.ival1.tv_usec = 1000;
		msg.msg_head.ival2.tv_sec = 0;
		msg.msg_head.ival2.tv_usec = 0;

		/* fill data that shows the variables */
		for (i = 0; i < NFRAMES; i++) {
			msg.frame[i].can_id = loops;
			msg.frame[i].len = (i & 7) + 1;
			msg.frame[i].data[0] = i;
		}

		if (write(s, &msg, sizeof(msg)) < 0)
			perror("write");
	}

	usleep(20000);

	msg.msg_head.opcode  = TX_SETUP;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = SETTIMER|STARTTIMER;
	msg.msg_head.nframes = NFRAMES/2;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 0;
	msg.frame[0].can_id    = 0x42;
	msg.frame[0].can_dlc   = 8;
	U64_DATA(&msg.frame[0]) = (__u64) 0xdeadbeefdeadbeefULL;

	if (write(s, &msg, sizeof(msg)) < 0)
		perror("write");

	usleep(20000);

	for (loops = 1; loops < LOOPS; loops++) {

		/* vary the time to update the bcm operation */
		usleep(2900 + 9 * loops);

		/* set header values */
		msg.msg_head.opcode  = TX_SETUP;
		msg.msg_head.can_id  = 0x42;

		if (loops & 3)
			msg.msg_head.flags = SETTIMER|STARTTIMER;
		else
			msg.msg_head.flags = 0;

		/* test TX_RESET_MULTI_IDX */
		if (loops & 16)
			msg.msg_head.flags |= TX_RESET_MULTI_IDX;

		msg.msg_head.nframes = NFRAMES/2;
		msg.msg_head.count = 8;
		msg.msg_head.ival1.tv_sec = 0;
		msg.msg_head.ival1.tv_usec = 1000;
		msg.msg_head.ival2.tv_sec = 0;
		msg.msg_head.ival2.tv_usec = 0;

		/* fill data that shows the variables */
		for (i = 0; i < NFRAMES; i++) {
			msg.frame[i].can_id = loops;
			msg.frame[i].len = (i & 7) + 1;
			msg.frame[i].data[0] = i;
		}

		if (write(s, &msg, sizeof(msg)) < 0)
			perror("write");
	}

	usleep(20000);

	msg.msg_head.opcode  = TX_SETUP;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = SETTIMER|STARTTIMER;
	msg.msg_head.nframes = 1;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 0;
	msg.frame[0].can_id    = 0x42;
	msg.frame[0].can_dlc   = 8;
	U64_DATA(&msg.frame[0]) = (__u64) 0xdeadbeefdeadbeefULL;

	if (write(s, &msg, sizeof(msg)) < 0)
		perror("write");

	close(s);
	return 0;
}
