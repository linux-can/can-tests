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

PROGRAMS = 	raw/tst-raw			\
		raw/tst-raw-filter		\
		raw/tst-err			\
		raw/tst-raw-sendto		\
		raw/canpump			\
		raw/canecho			\
		netlayer/tst-packet		\
		netlayer/tst-filter		\
		netlayer/tst-filter-master	\
		netlayer/tst-filter-server	\
		netlayer/tst-rcv-own-msgs	\
		netlayer/tst-proc		\
		bcm/tst-bcm-cycle		\
		bcm/tst-bcmfd-cycle		\
		bcm/tst-bcm-tx_read		\
		bcm/tst-bcm-tx_delete		\
		bcm/tst-bcm-rtr			\
		bcm/tst-bcm-single		\
		bcm/tst-bcm-filter		\
		bcm/tst-bcmfd-filter		\
		bcm/tst-bcm-throttle		\
		bcm/tst-bcm-rx-sendto		\
		bcm/tst-bcm-tx-sendto		\
		bcm/tst-bcm-dump		\
		gw/gwtest

all: $(PROGRAMS)

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin

clean:
	rm -f $(PROGRAMS) *.o

distclean:
	rm -f $(PROGRAMS) *.o *~

canpump:	raw/canpump.o	lib/lib.o
