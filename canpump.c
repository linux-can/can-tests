/*
 * canpump.c - reduced CAN data logger using recvmmsg() syscall
 *
 * Copyright (c) 2014 Oliver Hartkopp <socketcan@hartkopp.net>
 *
 * contains portions of candump.c and the recvmmsg(8) man page
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "lib.h"

#define ANYDEV "any"  /* name of interface to receive from any CAN interface */
#define MAXIFNAMES 30 /* size of receive name index to omit ioctls */

/* we only support one socket */
static __u32 dropcnt;
static __u32 last_dropcnt;

static char devname[MAXIFNAMES][IFNAMSIZ+1];
static int  dindex[MAXIFNAMES];
static int  max_devname_len; /* to prevent frazzled device name output */

int idx2dindex(int ifidx, int socket) {

	int i;
	struct ifreq ifr;

	for (i=0; i < MAXIFNAMES; i++) {
		if (dindex[i] == ifidx)
			return i;
	}

	/* create new interface index cache entry */

	/* remove index cache zombies first */
	for (i=0; i < MAXIFNAMES; i++) {
		if (dindex[i]) {
			ifr.ifr_ifindex = dindex[i];
			if (ioctl(socket, SIOCGIFNAME, &ifr) < 0)
				dindex[i] = 0;
		}
	}

	for (i=0; i < MAXIFNAMES; i++)
		if (!dindex[i]) /* free entry */
			break;

	if (i == MAXIFNAMES) {
		fprintf(stderr, "Interface index cache only supports %d interfaces.\n",
		       MAXIFNAMES);
		exit(1);
	}

	dindex[i] = ifidx;

	ifr.ifr_ifindex = ifidx;
	if (ioctl(socket, SIOCGIFNAME, &ifr) < 0)
		perror("SIOCGIFNAME");

	if (max_devname_len < strlen(ifr.ifr_name))
		max_devname_len = strlen(ifr.ifr_name);

	strcpy(devname[i], ifr.ifr_name);

#ifdef DEBUG
	printf("new index %d (%s)\n", i, devname[i]);
#endif

	return i;
}

#define VLEN 20

int main(int argc, char **argv)
{
	int s; /* can raw socket */
	int enable_sockopt = 1;
	struct sockaddr_can addr;
	struct sockaddr_can addrs[VLEN];
	struct ifreq ifr;

	char ctrlmsgs[VLEN][CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
	struct cmsghdr *cmsg;

	struct canfd_frame frames[VLEN];
	struct iovec iovecs[VLEN];
	struct mmsghdr mmsghdrs[VLEN];

	char buf[CL_CFSZ]; /* max length */
	int nframes, maxdlen, idx, i;
	struct timeval tv = { 0, 0 };

	/* check command line options */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <device>.\n", argv[0]);
		return 1;
	}

	/* open socket */
	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = AF_CAN;

	strcpy(ifr.ifr_name, argv[1]);

	if (strcmp(ANYDEV, ifr.ifr_name)) {
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			exit(1);
		}
		addr.can_ifindex = ifr.ifr_ifindex;
	} else
		addr.can_ifindex = 0; /* any can interface */

	/* try to switch the socket into CAN FD mode */
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_sockopt, sizeof(enable_sockopt));

	if (setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &enable_sockopt, sizeof(enable_sockopt)) < 0) {
		perror("setsockopt SO_TIMESTAMP");
		return 1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_RXQ_OVFL, &enable_sockopt, sizeof(enable_sockopt)) < 0) {
		perror("setsockopt SO_RXQ_OVFL not supported by your Linux Kernel");
		/* continue without dropmonitor */
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	/* these settings are static and can be held out of the hot path */
	memset(frames, 0, sizeof(frames));
	memset(addrs, 0, sizeof(addrs));
	memset(iovecs, 0, sizeof(iovecs));
	memset(mmsghdrs, 0, sizeof(mmsghdrs));
	for (i = 0; i < VLEN; i++) {
		iovecs[i].iov_base = &frames[i];
//		iovecs[i].iov_len = BUFSIZE;
		mmsghdrs[i].msg_hdr.msg_name= &addrs[i];
		mmsghdrs[i].msg_hdr.msg_iov = &iovecs[i];
		mmsghdrs[i].msg_hdr.msg_iovlen = 1;
		mmsghdrs[i].msg_hdr.msg_control = &ctrlmsgs[i];
	}

//	iov.iov_base = &frame;
//	msg.msg_name = &addr;
//	msg.msg_iov = &iov;
//	msg.msg_iovlen = 1;
//	msg.msg_control = &ctrlmsg;

	nframes = VLEN;

	while (1) {

		/* these settings may be modified by recvmsg() */
		for (i = 0; i < nframes; i++) {
			iovecs[i].iov_len = sizeof(frames[0]);
			mmsghdrs[i].msg_hdr.msg_namelen = sizeof(addrs[0]);
			mmsghdrs[i].msg_hdr.msg_controllen = sizeof(ctrlmsgs[0]);
			mmsghdrs[i].msg_hdr.msg_flags = 0;
		}

//		iov.iov_len = sizeof(frame);
//		msg.msg_namelen = sizeof(addr);
//		msg.msg_controllen = sizeof(ctrlmsg);
//		msg.msg_flags = 0;

		nframes = recvmmsg(s, mmsghdrs, VLEN, MSG_WAITFORONE, NULL);
		if (nframes < 0) {
			perror("recvmmsg()");
			return 1;
		}

		for (i = 0; i < nframes; i++) {

			if ((size_t)mmsghdrs[i].msg_len == CAN_MTU)
				maxdlen = CAN_MAX_DLEN;
			else if ((size_t)mmsghdrs[i].msg_len == CANFD_MTU)
				maxdlen = CANFD_MAX_DLEN;
			else {
				fprintf(stderr, "read: incomplete CAN frame\n");
				return 1;
			}

			for (cmsg = CMSG_FIRSTHDR(&mmsghdrs[i].msg_hdr);
			     cmsg && (cmsg->cmsg_level == SOL_SOCKET);
			     cmsg = CMSG_NXTHDR(&mmsghdrs[i].msg_hdr,cmsg)) {
				if (cmsg->cmsg_type == SO_TIMESTAMP)
					tv = *(struct timeval *)CMSG_DATA(cmsg);
				else if (cmsg->cmsg_type == SO_RXQ_OVFL)
					dropcnt = *(__u32 *)CMSG_DATA(cmsg);
			}

			/* check for (unlikely) dropped frames on this specific socket */
			if (dropcnt != last_dropcnt) {

				__u32 drops;

				if (dropcnt > last_dropcnt)
					drops = dropcnt - last_dropcnt;
				else
					drops = UINT32_MAX - last_dropcnt + dropcnt;

				printf("DROPCOUNT: dropped %d CAN frame%s (total drops %d)\n",
				       drops, (drops > 1)?"s":"", dropcnt);

					last_dropcnt = dropcnt;
			}

			idx = idx2dindex(addrs[i].can_ifindex, s);

			/* print CAN frame in log file style to stdout */
			sprint_canframe(buf, &frames[i], 0, maxdlen);
#if 1
			printf("(%010ld.%06ld) %*s %s\n",
			       tv.tv_sec, tv.tv_usec,
			       max_devname_len, devname[idx], buf);
#else
			printf("(%010ld.%06ld) %*s %s ((%dv%d))\n",
			       tv.tv_sec, tv.tv_usec,
			       max_devname_len, devname[idx], buf, i+1, nframes);
#endif
			fflush(stdout);
		}
	}

	close(s);

	return 0;
}
