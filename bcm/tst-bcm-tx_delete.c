/*
 * tst-bcm-tx_delete.c
 *
 * Copyright (c) 2016 Volkswagen Group Electronic Research
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

int main(int argc, char **argv)
{
	int s;
	struct sockaddr_can addr;
	struct ifreq ifr;

	struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame;
	} msg;

	struct {
		struct bcm_msg_head msg_head;
		struct canfd_frame frame;
	} fdmsg;

	if ((s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM)) < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = PF_CAN;
	strcpy(ifr.ifr_name, "vcan2");
	ioctl(s, SIOCGIFINDEX, &ifr);
	addr.can_ifindex = ifr.ifr_ifindex;

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	msg.msg_head.opcode  = TX_SETUP;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = SETTIMER|STARTTIMER|TX_CP_CAN_ID;
	msg.msg_head.nframes = 1;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 1;
	msg.frame.can_dlc   = 8;
	U64_DATA(&msg.frame) = (__u64) 0xdeadbeefdeadbeefULL;

	if (write(s, &msg, sizeof(msg)) < 0)
		perror("write");

	printf("Press any key to stop the cycle ...\n");

	getchar();

	msg.msg_head.opcode  = TX_DELETE;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = 0;
	msg.msg_head.nframes = 0;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 0;

	if (write(s, &msg, sizeof(struct bcm_msg_head)) < 0)
		perror("write");

	printf("Press any key to start the FD cycle ...\n");

	getchar();

	fdmsg.msg_head.opcode  = TX_SETUP;
	fdmsg.msg_head.can_id  = 0x42;
	fdmsg.msg_head.flags   = SETTIMER|STARTTIMER|TX_CP_CAN_ID|CAN_FD_FRAME;
	fdmsg.msg_head.nframes = 1;
	fdmsg.msg_head.count = 0;
	fdmsg.msg_head.ival1.tv_sec = 0;
	fdmsg.msg_head.ival1.tv_usec = 0;
	fdmsg.msg_head.ival2.tv_sec = 0;
	fdmsg.msg_head.ival2.tv_usec = 1;
	fdmsg.frame.len = 8;
	U64_DATA(&fdmsg.frame) = (__u64) 0xdeadbeefdeadbeefULL;

	if (write(s, &fdmsg, sizeof(fdmsg)) < 0)
		perror("write");

	printf("Press any key to stop the cycle ...\n");

	getchar();

	fdmsg.msg_head.opcode  = TX_DELETE;
	fdmsg.msg_head.can_id  = 0x42;
	fdmsg.msg_head.flags   = CAN_FD_FRAME;
	fdmsg.msg_head.nframes = 0;
	fdmsg.msg_head.count = 0;
	fdmsg.msg_head.ival1.tv_sec = 0;
	fdmsg.msg_head.ival1.tv_usec = 0;
	fdmsg.msg_head.ival2.tv_sec = 0;
	fdmsg.msg_head.ival2.tv_usec = 0;

	if (write(s, &fdmsg, sizeof(struct bcm_msg_head)) < 0)
		perror("write");

	printf("Press any key to close the socket ...\n");

	getchar();

	close(s);

	printf("done\n");

	return 0;
}
