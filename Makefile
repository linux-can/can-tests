# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
#  Copyright (c) 2002-2007 Volkswagen Group Electronic Research
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions, the following disclaimer and
#     the referenced file 'COPYING'.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of Volkswagen nor the names of its contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
#  Alternatively, provided that this notice is retained in full, this
#  software may be distributed under the terms of the GNU General
#  Public License ("GPL") version 2 as distributed in the 'COPYING'
#  file from the main directory of the linux kernel source.
#
#  The provided data structures and external interfaces from this code
#  are not restricted to be used by modules with a GPL compatible license.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#
#  Send feedback to <linux-can@vger.kernel.org>

DESTDIR ?=
PREFIX ?= /usr/local

MAKEFLAGS = -k

CFLAGS    = -O2 -Wall -Wno-parentheses \
	    -fno-strict-aliasing

CPPFLAGS += -Iinclude \
	    -Ilib \
	    -D_FILE_OFFSET_BITS=64 \
	    -DSO_RXQ_OVFL=40 \
	    -DETH_P_CAN=0x000C \
	    -DPF_CAN=29 \
	    -DAF_CAN=PF_CAN

PROGRAMS := \
	bcm/tst-bcm-cycle \
	bcm/tst-bcm-dump \
	bcm/tst-bcm-filter \
	bcm/tst-bcm-rtr \
	bcm/tst-bcm-rx-sendto \
	bcm/tst-bcm-single \
	bcm/tst-bcm-throttle \
	bcm/tst-bcm-tx-sendto \
	bcm/tst-bcm-tx-delete \
	bcm/tst-bcm-tx-read \
	bcm/tst-bcmfd-cycle \
	bcm/tst-bcmfd-filter \
	bcm/cansniffer \
	drv/canfdtest \
	gw/gwtest \
	netlayer/tst-filter \
	netlayer/tst-filter-master \
	netlayer/tst-filter-server \
	netlayer/tst-packet \
	netlayer/tst-proc \
	netlayer/tst-rcv-own-msgs \
	raw/canecho \
	raw/canpump \
	raw/tst-err \
	raw/tst-raw \
	raw/tst-raw-filter \
	raw/tst-raw-sockopt \
	raw/tst-raw-sendto \
	j1939/tst-j1939-ac

J1939 := \
	j1939/j1939_ac_100k_dual_can.sh \
	j1939/j1939_ac_100k_local0.sh \
	j1939/j1939_ac_1k_bam_local0.sh \
	j1939/j1939_ac_1k_local0.sh \
	j1939/j1939_ac_1m_local0.sh \
	j1939/j1939_ac_8b_local0.sh \
	j1939/j1939_multisock_dualack_100k.sh \
	j1939/j1939_multisock_dualack_1k.sh \
	j1939/j1939_multisock_timeout_100k.sh \
	j1939/run_all.sh

all: $(PROGRAMS)

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/can-tests/j1939
	cp -f $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin
	cp -f $(J1939) $(DESTDIR)$(PREFIX)/lib/can-tests/j1939

clean:
	rm -f $(PROGRAMS) */*.o

distclean:
	rm -f $(PROGRAMS) *.o *~

bcm/cansniffer.o: lib/lib.h
bcm/cansniffer: bcm/cansniffer.o lib/lib.o
raw/canpump.o: lib/lib.h
raw/canpump: raw/canpump.o lib/lib.o
