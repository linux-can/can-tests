/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * tst-raw-sockopt.c
 *
 * Copyright (c) 2020 Volkswagen Group Electronic Research
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#define MAXFILTERS 32
#define FSZ ((socklen_t)sizeof(struct can_filter))

#define MAXSZ (MAXFILTERS * FSZ)

#define RIGHTSZ (16 * FSZ) /* filters set by setsockopt */
#define LESSSZ (10 * FSZ) /* getsockopt test with smaller buffer */
#define MORESZ (20 * FSZ) /* getsockopt test with bigger buffer */

int main(int argc, char **argv)
{
	int s;
	struct can_filter rfilter[MAXFILTERS];
	int ret;
	socklen_t optlen;

	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	/* no need to bind the socket to an interface for this test */

	errno = 0;
	ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, RIGHTSZ);
	printf("setsockopt: write %u byte -> %s\n", RIGHTSZ, strerror(errno));

	if (ret < 0) {
		printf("setsockopt: Unexpected error %s\n", strerror(errno));
		return 1;
	}

	/* provide a buffer that has exactly the needed space */
	optlen = RIGHTSZ;
	errno = 0;
	ret = getsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, &optlen);
	printf("getsockopt1: read %u byte into %u byte buffer -> %s\n", RIGHTSZ, RIGHTSZ, strerror(errno));

	if (optlen != RIGHTSZ)
		printf("getsockopt1: optlen %u expected %u\n", optlen, RIGHTSZ);

	if (ret < 0) {
		printf("getsockopt1: Unexpected error %s\n", strerror(errno));
		return 1;
	}

	/* provide a buffer that has more space than needed */
	optlen = MORESZ;
	errno = 0;
	ret = getsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, &optlen);
	printf("getsockopt2: read %u byte into %u byte buffer -> %s\n", RIGHTSZ, MORESZ, strerror(errno));

	if (optlen != RIGHTSZ)
		printf("getsockopt2: optlen %u expected %u\n", optlen, RIGHTSZ);

	if (ret < 0) {
		printf("getsockopt2: Unexpected error %s\n", strerror(errno));
		return 1;
	}

	/* provide a buffer that has less space than needed */
	optlen = LESSSZ;
	errno = 0;
	ret = getsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, &optlen);
	printf("getsockopt3: read %u byte into %u byte buffer -> %s\n", RIGHTSZ, LESSSZ, strerror(errno));

	/* old behaviour: the kernel silently truncated the filterset to LESSSZ */
	if (ret == 0) {
		if (optlen != LESSSZ) {
			/* the buffer should be filled up completely */
			printf("getsockopt3: optlen %u expected %u\n", optlen, LESSSZ);
			return 1;
		}

		/* the kernel silently truncated the filterset to LESSSZ */
		printf("getsockopt3: buffer too small for filter but no error\n");
		return 1;
	}

	/* does the kernel support ERANGE to provide the needed length? */
	if (errno != ERANGE) {
		/* No. Then print the unexpected error (potentially -EFAULT) */
		printf("getsockopt3: Unexpected error %s\n", strerror(errno));
		return 1;
	}

	/* -ERANGE -> the needed length was returned in optlen */
	if (optlen != RIGHTSZ) {
		/* the kernel should have returned RIGHTSZ in optlen */
		printf("getsockopt3: optlen %u expected %u\n", optlen, RIGHTSZ);
		return 1;
	}

	/* retry with returned optlen value */
	errno = 0;
	ret = getsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, &optlen);
	printf("getsockopt4: read %u byte into %u byte buffer -> %s\n", RIGHTSZ, RIGHTSZ, strerror(errno));

	if (optlen != RIGHTSZ)
		printf("getsockopt4: optlen %u expected %u\n", optlen, RIGHTSZ);

	if (ret < 0) {
		printf("getsockopt4: Unexpected error %s\n", strerror(errno));
		return 1;
	}

	close(s);

	return 0;
}
