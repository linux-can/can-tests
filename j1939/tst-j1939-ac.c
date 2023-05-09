// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <entwicklung@pengutronix.de>

/*
 * The tst-j1939-ac.c file contains a series of test functions designed to
 * evaluate the kernel side helpers for the J1939 Address Claiming support.
 * These tests aim to verify the correct functioning of the J1939/ISOBUS
 * traffic monitoring, the internal cache of NAMEs with address mapping, as
 * well as the resolution of NAMEs for ingress and egress packets.
 *
 * In addition, the tests evaluate the behavior of kernel J1939 stack when
 * applying certain restrictions. For example, the tests examine the
 * enforcement of a 250ms pause between address claimed messages and the
 * rest of the communication, ensuring that the address claiming procedure
 * is properly completed. The file includes test cases for various scenarios
 * where the pause is necessary and cases where it is not. This helps ensure
 * that the kernel side helpers are correctly handling the J1939 Address
 * Claiming process and providing the expected support to user space
 * applications.
 */

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include <linux/errqueue.h>
#include <linux/netlink.h>
#include <linux/net_tstamp.h>
#include <linux/can/j1939.h>

/*
 * TST_J1939_AC_DEFAULT_INTERFACE: Default CAN interface used for J1939 address
 *				   claiming tests
 * TST_J1939_AC_NAME1: A random 64-bit J1939 name used for testing purposes
 *		       (socket 1)
 * TST_J1939_AC_NAME2: A random 64-bit J1939 name used for testing purposes
 *		       (socket 2)
 * TST_J1939_AC_ADDR1: A random J1939 address used for testing purposes
 *		       (socket 1)
 * TST_J1939_AC_ADDR2: A random J1939 address used for testing purposes
 *		       (socket 2)
 *
 * These definitions provide default values for the test setup, including the
 * CAN interface, J1939 names, and J1939 addresses used in the address claiming
 * test cases.
 */
#define TST_J1939_AC_DEFAULT_INTERFACE "vcan0"
#define TST_J1939_AC_NAME1 0x1122334455667788ULL
#define TST_J1939_AC_NAME2 0x1122334455667789ULL
#define TST_J1939_AC_ADDR1 0x88
#define TST_J1939_AC_ADDR2 0x89

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct tst_j1939_ac_stats {
	int err;
	uint32_t tskey_sch;
	uint32_t tskey_ack;
	uint32_t send;
	/* time where message was send from user space to the socket */
	struct timespec tx_send_time;
	/* time when the message was scheduled for sending from J1939 to
	 * af_can
	 */
	struct timespec tx_schd_time;
	/* time when the message was sent to a bus or aborted */
	struct timespec tx_done_time;
	bool done;
};

struct tst_j1939_ac_err_msg {
	struct sock_extended_err *serr;
	struct scm_timestamping *tss;
	struct tst_j1939_ac_stats *stats;
};

/*
 * enum tst_j1939_ac_socks - Enumeration of socket types for J1939 address
 *			     claiming tests
 *
 * TST_J1939_AC_SOCK_AC1: First address claiming socket
 * TST_J1939_AC_SOCK_TX1: First ping transmitting socket
 * TST_J1939_AC_SOCK_AC2: Second address claiming socket
 * TST_J1939_AC_SOCK_TX2: Second ping transmitting socket
 * TST_J1939_AC_SOCK_MAX: Maximum number of socket types, used for validation
 *			  purposes
 */
enum tst_j1939_ac_socks {
	TST_J1939_AC_SOCK_AC1,
	TST_J1939_AC_SOCK_TX1,
	TST_J1939_AC_SOCK_AC2,
	TST_J1939_AC_SOCK_TX2,
	TST_J1939_AC_SOCK_MAX,
};

struct tst_j1939_ac_priv;

/*
 * struct tst_j1939_ac_sock - Structure for J1939 address claiming test sockets
 *
 * @fd: File descriptor of the socket
 * @name: 64-bit J1939 NAME for the socket
 * @addr: 8-bit J1939 address for the socket
 * @stats: tst_j1939_ac_stats structure to keep track of socket's statistics
 * @sock_type: Type of the socket, as defined by the tst_j1939_ac_socks
 *             enumeration
 * @priv: Pointer to the tst_j1939_ac_priv structure for sharing data between
 *        sockets
 */
struct tst_j1939_ac_sock {
	int fd;
	uint64_t name;
	uint8_t addr;
	struct tst_j1939_ac_stats stats;
	enum tst_j1939_ac_socks sock_type;
	struct tst_j1939_ac_priv *priv;
};

/*
 * struct tst_j1939_ac_priv - Structure for J1939 address claiming test private
 *			      data
 *
 * @socks: Array of tst_j1939_ac_sock structures, representing the test sockets
 * @socks_mask: 32-bit bitmask for selectively enabling or disabling specific
 *		sockets
 * @epoll_fd: File descriptor for epoll instance used to manage socket events
 * @epoll_events: Array of epoll_event structures to store events related to
 *		  sockets
 * @epoll_events_size: Size of the epoll_events array
 * @can_ifindex: CAN interface index for the test
 * @current_test: Index of the currently running test
 * @all_tests_completed: Boolean flag indicating whether all tests have been
 *			 completed
 * @test_start_time: Timestamp for the start of the current test state
 * @state: Current state of the state machine, using the tst_j1939_ac_cli_state
 *	   enumeration
 */
struct tst_j1939_ac_priv {
	struct tst_j1939_ac_sock socks[TST_J1939_AC_SOCK_MAX];
	uint32_t socks_mask;

	int epoll_fd;
	struct epoll_event epoll_events[TST_J1939_AC_SOCK_MAX];
	size_t epoll_events_size;

	uint32_t can_ifindex;

	size_t current_test;
	bool all_tests_completed;
	struct timespec test_start_time;

	int state;
};

/*
 * tst_j1939_ac_sock_init - Initialize a J1939 AC test socket
 * @priv: Pointer to the tst_j1939_ac_priv structure
 * @sock_type: Enumeration value representing the type of socket to initialize
 * @name: 64-bit J1939 name for the socket
 * @saddr: Source address for the socket
 *
 * This function initializes a J1939 AC test socket with the specified name and
 * source address. It sets the necessary socket options, binds the socket to the
 * CAN interface, and adds the socket to the epoll instance for event
 * monitoring. It also stores the socket type and a reference to the private
 * data structure in the socket structure.
 */
static void tst_j1939_ac_sock_init(struct tst_j1939_ac_priv *priv,
                                   enum tst_j1939_ac_socks sock_type,
                                   uint64_t name, uint8_t saddr) {
        struct tst_j1939_ac_sock *sock = &priv->socks[sock_type];
        struct sockaddr_can addr = {0};
        struct epoll_event ev = {0};
        unsigned int sock_opt;
        int val_true = 1;
        int ret;

        sock->fd = socket(AF_CAN, SOCK_DGRAM, CAN_J1939);
	if (sock->fd < 0)
		err(EXIT_FAILURE, "socket");

	addr.can_family = AF_CAN;
	addr.can_ifindex = priv->can_ifindex;
	addr.can_addr.j1939.name = name;
	addr.can_addr.j1939.addr = saddr;
	addr.can_addr.j1939.pgn = J1939_NO_PGN;

	sock->name = name;
	sock->sock_type = sock_type;
	sock->priv = priv;

	ret = bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		err(EXIT_FAILURE, "bind");

	/* for Address Claiming broadcast must be allowed */
	ret = setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &val_true,
			 sizeof(val_true));
	if (ret < 0)
		err(EXIT_FAILURE, "setsockopt: BROADCAST");

	ret = setsockopt(sock->fd, SOL_CAN_J1939, SO_J1939_ERRQUEUE, &val_true,
			 sizeof(val_true));
	if (ret < 0)
		err(EXIT_FAILURE, "setsockopt: ERRQUEUE");

	sock_opt = SOF_TIMESTAMPING_SOFTWARE |
		   SOF_TIMESTAMPING_OPT_CMSG |
		   SOF_TIMESTAMPING_TX_ACK |
		   SOF_TIMESTAMPING_TX_SCHED |
		   SOF_TIMESTAMPING_OPT_STATS | SOF_TIMESTAMPING_OPT_TSONLY |
		   SOF_TIMESTAMPING_OPT_ID | SOF_TIMESTAMPING_RX_SOFTWARE;

	ret = setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMPING,
			 (char *)&sock_opt, sizeof(sock_opt));
	if (ret)
		err(EXIT_FAILURE, "setsockopt: timestamping");

	ev.events = EPOLLERR;
	ev.data.ptr = sock;
	ret = epoll_ctl(priv->epoll_fd, EPOLL_CTL_ADD, sock->fd, &ev);
	if (ret < 0)
		err(EXIT_FAILURE, "epoll_ctl");
}

/*
 * tst_j1939_ac_timespec_diff_ms - Calculate the time difference between two
 *				   timespecs in milliseconds
 * @ts1: Pointer to the first timespec structure
 * @ts2: Pointer to the second timespec structure
 *
 * This function calculates the time difference between two timespec structures
 * in milliseconds, taking into account both the seconds and nanoseconds
 * components.
 *
 * Return: The time difference in milliseconds as an int64_t value.
 */
static int64_t tst_j1939_ac_timespec_diff_ms(struct timespec *ts1,
					     struct timespec *ts2)
{
	int64_t diff = (ts1->tv_sec - ts2->tv_sec) * 1000;

	diff += (ts1->tv_nsec - ts2->tv_nsec) / 1000000;

	return diff;
}

struct tst_j1939_ac_cli_test_case {
	int (*test_func)(struct tst_j1939_ac_priv *priv, bool *complete);
	const char *test_description;
};

/*
 * tst_j1939_ac_send - Send a message
 * @sock: Pointer to the tst_j1939_ac_sock structure
 * @buf: Pointer to the buffer containing the message to send
 * @len: Length of the message in the buffer
 * @addr: Pointer to the sockaddr_can structure containing the destination
 *	  address
 * @no_addr_ok: Flag to indicate whether it is acceptable to silently skip
 *		sending if the socket is masked (true) or not (false)
 *
 * This function sends a message using the provided tst_j1939_ac_sock structure 
 * If the socket is masked, the function silently skips sending the
 * message based on the no_addr_ok flag. It also records the send time using the
 * system's monotonic clock for statistics purposes.
 *
 * Return: 0 on success, -EADDRNOTAVAIL if the address is not available and
 *         no_addr_ok is true, or it will exit with failure in case of other
 *	   errors.
 */
static int tst_j1939_ac_send(struct tst_j1939_ac_sock *sock,
			      void *buf, size_t len,
			      const struct sockaddr_can *addr,
			      bool no_addr_ok)
{
	int ret;

	/* silently skip sending if socket is masked */
	if (sock->priv->socks_mask & (1 << sock->sock_type))
		return 0;

	sock->stats.done = false;
	sock->stats.err = 0;
	ret = sendto(sock->fd, buf, len, MSG_DONTWAIT,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (ret < 0) {
		if (errno == EADDRNOTAVAIL && no_addr_ok)
			return -EADDRNOTAVAIL;

		err(EXIT_FAILURE, "sendto");
	}

	ret = clock_gettime(CLOCK_MONOTONIC, &sock->stats.tx_send_time);
	if (ret < 0)
		err(EXIT_FAILURE, "clock_gettime");

	return 0;
}

/*
 * tst_j1939_ac_claim_addr - Send an address claimed message for a provided
 *			     tst_j1939_ac_sock structure
 * @sock: Pointer to the tst_j1939_ac_sock structure
 *
 * This function sends an address claimed message for the provided
 * tst_j1939_ac_sock structure. It prepares a sockaddr_can structure with the
 * address family set to AF_CAN, the PGN set to J1939_PGN_ADDRESS_CLAIMED, and
 * the address set to J1939_NO_ADDR. Note that this function only sends the
 * address claimed message and does not follow the actual address claiming
 * procedure. It then sends the address claim using the tst_j1939_ac_send
 * function.
 */
static void tst_j1939_ac_claim_addr(struct tst_j1939_ac_sock *sock)
{
	const struct sockaddr_can daddr = {
		.can_family = AF_CAN,
		.can_addr.j1939 = {
			.pgn = J1939_PGN_ADDRESS_CLAIMED,
			.addr = J1939_NO_ADDR,
		},
	};
	__le64 dat = htole64(sock->name);

	tst_j1939_ac_send(sock, (void *)&dat, sizeof(dat), &daddr, false);
}

/*
 * tst_j1939_ac_send_ping - Send a ping message using the provided
 *			    tst_j1939_ac_sock structure
 * @sock: Pointer to the tst_j1939_ac_sock structure
 * @addr: 8-bit destination address for the ping message
 *
 * This function sends a ping message using the provided tst_j1939_ac_sock
 * structure. It prepares a sockaddr_can structure with the destination address
 * family set to AF_CAN, the PGN set to a random PGN number (0x0aa00), the
 * address set to the specified addr, and the name set to J1939_NO_NAME. This
 * PGN number can be replaced if needed. It then sends the ping message using
 * the tst_j1939_ac_send function, allowing for the case where the address might
 * not be available (no_addr_ok is true).
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int tst_j1939_ac_send_ping(struct tst_j1939_ac_sock *sock, uint8_t addr)
{
	const struct sockaddr_can daddr = {
		.can_family = AF_CAN,
		.can_addr.j1939 = {
			.name = J1939_NO_NAME,
			.pgn = 0x0aa00,
			.addr = addr,
		},
	};
	__le64 dat = htole64(sock->name);

	return tst_j1939_ac_send(sock, (void *)&dat, sizeof(dat), &daddr, true);
}

/*
 * tst_j1939_ac_cli_state - Enumeration of states for the tests state machine
 *
 * This enumeration defines the states used in the state machine for managing
 * the J1939 address claiming tests. The state machine goes through the
 * following states:
 *
 * TST_J1939_AC_TEST_START: The initial state when the test starts
 * TST_J1939_AC_WAIT_AC_DONE1: Waiting for the first address claim to complete
 * TST_J1939_AC_AC_SEND_DONE1: First address claim has been sent
 * TST_J1939_AC_WAIT_PING_DONE1: Waiting for the first ping to complete
 * TST_J1939_AC_AC_CLAIM_ADDR2: Claiming the second address
 * TST_J1939_AC_WAIT_AC_DONE2: Waiting for the second address claim to complete
 * TST_J1939_AC_AC_SEND_DONE2: Second address claim has been sent
 * TST_J1939_AC_WAIT_PING_DONE2: Waiting for the second ping to complete
 * TST_J1939_AC_CLEANUP: Cleanup state after the tests have been completed
 */
enum tst_j1939_ac_cli_state {
	/* 0 is reserved for the initial state */
	TST_J1939_AC_TEST_START = 1,
	TST_J1939_AC_WAIT_AC_DONE1,
	TST_J1939_AC_AC_SEND_DONE1,
	TST_J1939_AC_WAIT_PING_DONE1,
	TST_J1939_AC_AC_CLAIM_ADDR2,
	TST_J1939_AC_WAIT_AC_DONE2,
	TST_J1939_AC_AC_SEND_DONE2,
	TST_J1939_AC_WAIT_PING_DONE2,
	TST_J1939_AC_CLEANUP,
};

/*
 * tst_j1939_ac_test_250_wait - Test kernel behavior for J1939 address claiming
 *                               with 250ms wait
 * @priv: Pointer to the tst_j1939_ac_priv structure
 * @complete: Pointer to a boolean flag indicating test completion
 *
 * This function is designed to test the Linux kernel's behavior for the J1939
 * address claiming specification. The test case ensures that the kernel will
 * prevent user space from sending messages with the source NAME until the
 * required timeout of 250ms is completed.
 *
 * The test creates 4 sockets: 2 for address claiming and 2 for ping sending.
 * The ping sockets are bound to source NAMEs only, with no source addresses
 * set. The test claims different addresses for two different NAMEs and then
 * attempts to send a message over the 2 separate ping sockets using NAMEs only.
 *
 * If a message is sent before the 250ms window, the test fails. If a message is
 * not sent after 250ms, the test also fails.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int tst_j1939_ac_test_250_wait(struct tst_j1939_ac_priv *priv,
                                      bool *complete) {
        struct timespec current_time;
        int ret1, ret2;
        int64_t diff;

        clock_gettime(CLOCK_MONOTONIC, &current_time);

	switch (priv->state) {
	case TST_J1939_AC_TEST_START:
		priv->test_start_time = current_time;

		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC1,
				       TST_J1939_AC_NAME1, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX1,
				       TST_J1939_AC_NAME1, J1939_NO_ADDR);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC2,
				       TST_J1939_AC_NAME2, TST_J1939_AC_ADDR2);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX2,
				       TST_J1939_AC_NAME2, J1939_NO_ADDR);

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC1]);
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC2]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE1;

		break;
	case TST_J1939_AC_WAIT_AC_DONE1:
		if (priv->socks[TST_J1939_AC_SOCK_AC1].stats.done &&
		    priv->socks[TST_J1939_AC_SOCK_AC2].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE1;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE1:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		if (!ret1)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX1);
		ret2 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR1);
		if (!ret2)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX2);

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* after successful address claim, we expect the ping not beeng
		 * send for 250ms.
		 */
		if (ret1 < 0 || ret2 < 0) {
			/* 250ms timeout is expected after the address claim.
			 * add some more milliseconds to not accidentally fail
			 */
			if (diff < 252)
				break;

			errx(EXIT_FAILURE, "send ping1 to socket failed");
		} else if (!ret1 && !ret2) {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->socks_mask = 0;
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE1;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE1:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send ping1 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_AC1].stats.done &&
		    !priv->socks[TST_J1939_AC_SOCK_AC2].stats.done)
			break;

		priv->state = TST_J1939_AC_CLEANUP;
		break;
	case TST_J1939_AC_CLEANUP:
		for (int i = 0; i < TST_J1939_AC_SOCK_MAX; i++) {
			epoll_ctl(priv->epoll_fd, EPOLL_CTL_DEL,
				  priv->socks[i].fd, NULL);
			close(priv->socks[i].fd);
		}

		*complete = true;
		break;
	default:
		errx(EXIT_FAILURE, "unknown state: %d", priv->state);
		ret1 = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	/* without server all other tests make no sense */
	priv->all_tests_completed = true;
	*complete = true;

	return ret1;
}

/*
 * tst_j1939_ac_test_second_ac_no_wait - Test kernel behavior for J1939 address
 *                                       claiming with no wait on second claim
 * @priv: Pointer to the tst_j1939_ac_priv structure
 * @complete: Pointer to a boolean flag indicating test completion
 *
 * This function is designed to test the Linux kernel's behavior for the J1939
 * address claiming specification, specifically focusing on the scenario where
 * an address is claimed for the second time.
 *
 * The first part of this test is identical to tst_j1939_ac_test_250_wait.
 * The test creates 4 sockets: 2 for address claiming and 2 for ping sending.
 * The ping sockets are bound to source NAMEs only, with no source addresses
 * set. The test claims different addresses for two different NAMEs and then
 * attempts to send a message over the 2 separate ping sockets using NAMEs only.
 *
 * The second part of this test resends address claims for the same NAME/address
 * tuples. In this case, it is expected that after the address is re-claimed,
 * no timeouts should be introduced. Packets should be sent immediately after
 * the re-claim.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int tst_j1939_ac_test_second_ac_no_wait(struct tst_j1939_ac_priv *priv,
                                               bool *complete) {
        struct timespec current_time;
        int ret1, ret2;
        int64_t diff;

        clock_gettime(CLOCK_MONOTONIC, &current_time);

	switch (priv->state) {
	case TST_J1939_AC_TEST_START:
		priv->test_start_time = current_time;

		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC1,
				       TST_J1939_AC_NAME1, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX1,
				       TST_J1939_AC_NAME1, J1939_NO_ADDR);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC2,
				       TST_J1939_AC_NAME2, TST_J1939_AC_ADDR2);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX2,
				       TST_J1939_AC_NAME2, J1939_NO_ADDR);

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC1]);
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC2]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE1;

		break;
	case TST_J1939_AC_WAIT_AC_DONE1:
		if (priv->socks[TST_J1939_AC_SOCK_AC1].stats.done &&
		    priv->socks[TST_J1939_AC_SOCK_AC2].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE1;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE1:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		if (!ret1)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX1);
		ret2 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR1);
		if (!ret2)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX2);
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* after successful address claim, we expect the ping not beeng
		 * send for 250ms.
		 */
		if (ret1 < 0 || ret2 < 0) {
			/* 250ms timeout is expected after the address claim.
			 * add some more milliseconds to not accidentally fail
			 */
			if (diff < 252)
				break;

			errx(EXIT_FAILURE, "send ping1 to socket failed");
		} else if (!ret1 && !ret2) {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->socks_mask = 0;
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE1;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE1:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send ping1 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX1].stats.done &&
		    !priv->socks[TST_J1939_AC_SOCK_TX2].stats.done)
			break;

		priv->state = TST_J1939_AC_AC_CLAIM_ADDR2;
		break;
	case TST_J1939_AC_AC_CLAIM_ADDR2:
		priv->test_start_time = current_time;

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC1]);
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC2]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE2;

		break;
	case TST_J1939_AC_WAIT_AC_DONE2:
		if (priv->socks[TST_J1939_AC_SOCK_AC1].stats.done &&
		    priv->socks[TST_J1939_AC_SOCK_AC2].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE2;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE2:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		if (!ret1)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX1);
		ret2 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR1);
		if (!ret2)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX2);
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* after successful address claim, we expect the ping not beeng
		 * send for 250ms.
		 */
		if (ret1 < 0 || ret2 < 0) {
			/* 250ms timeout is expected after the address claim.
			 * add some more milliseconds to not accidentally fail
			 */
			if (diff < 255)
				break;

			errx(EXIT_FAILURE, "send ping2 to socket failed");
		} else if (!ret1 && !ret2) {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->socks_mask = 0;
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE2;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE2:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send ping2 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX1].stats.done &&
		    !priv->socks[TST_J1939_AC_SOCK_TX2].stats.done)
			break;

		priv->state = TST_J1939_AC_CLEANUP;
		break;

	case TST_J1939_AC_CLEANUP:
		for (int i = 0; i < TST_J1939_AC_SOCK_MAX; i++) {
			epoll_ctl(priv->epoll_fd, EPOLL_CTL_DEL,
				  priv->socks[i].fd, NULL);
			close(priv->socks[i].fd);
		}

		*complete = true;
		break;
	default:
		errx(EXIT_FAILURE, "unknown state: %d", priv->state);
		ret1 = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	/* without server all other tests make no sense */
	priv->all_tests_completed = true;
	*complete = true;

	return ret1;
}

/*
 * tst_j1939_ac_test_addr_conflict1 - Test kernel behavior for J1939 address
 *                                    claiming with conflicting priorities
 * @priv: Pointer to the tst_j1939_ac_priv structure
 * @complete: Pointer to a boolean flag indicating test completion
 *
 * This function is designed to test the Linux kernel's behavior for the J1939
 * address claiming specification, specifically focusing on the scenario where
 * there is a conflict between high and low priority NAMEs.
 *
 * The test first claims an address with a higher priority. It then sends a ping
 * using this address and ensures that it is prevented for 250ms. After that,
 * the test claims the same address with a low priority NAME and attempts to
 * send pings using both source NAMEs. In this case, it is expected that the
 * ping with the high priority NAME should be able to send pings without delay,
 * while the pings with the low priority NAME should not be sent at all.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int tst_j1939_ac_test_addr_conflict1(struct tst_j1939_ac_priv *priv,
                                            bool *complete) {
        struct timespec current_time;
        int ret1, ret2;
        int64_t diff;

        clock_gettime(CLOCK_MONOTONIC, &current_time);

	switch (priv->state) {
	case TST_J1939_AC_TEST_START:
		priv->test_start_time = current_time;

		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC1,
				       TST_J1939_AC_NAME1, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX1,
				       TST_J1939_AC_NAME1, J1939_NO_ADDR);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC2,
				       TST_J1939_AC_NAME2, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX2,
				       TST_J1939_AC_NAME2, J1939_NO_ADDR);

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC1]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE1;

		break;
	case TST_J1939_AC_WAIT_AC_DONE1:
		if (priv->socks[TST_J1939_AC_SOCK_AC1].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE1;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE1:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/*
		 * After successful address claim, we expect the ping not being
		 * send for 250ms.
		 */
		if (ret1 < 0) {
			/*
			 * 250ms timeout is expected after the address claim.
			 * add some more milliseconds to not accidentally fail
			 */
			if (diff < 252)
				break;

			errx(EXIT_FAILURE, "send ping1 to socket failed");
		} else if (diff < 245) {
			/*
			 * Allow some jitter. On some qemu based systems it
			 * seems to be needed to avoid false positive errors.
			 */
			errx(EXIT_FAILURE, "send ping1 to socket succeeded too early: %" PRId64,
			     diff);
		} else {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE1;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE1:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send ping1 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX1].stats.done)
			break;

		priv->state = TST_J1939_AC_AC_CLAIM_ADDR2;
		break;
	case TST_J1939_AC_AC_CLAIM_ADDR2:
		priv->test_start_time = current_time;

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC2]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE2;

		break;
	case TST_J1939_AC_WAIT_AC_DONE2:
		if (priv->socks[TST_J1939_AC_SOCK_AC2].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE2;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE2:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		if (!ret1)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX1);
		ret2 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR1);
		if (!ret2)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX2);

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* TX1 should be able to send ping at any time. TX2 should not
		 * be able to send ping at all even after 250ms.
		 */

		if (ret1 < 0)
			errx(EXIT_FAILURE, "ping fox TX1 failed");


		if (!ret2)
			errx(EXIT_FAILURE, "ping fox TX2 should fail");

		/* take extra time to make sure we really are not able to send
		 * any thing at TX2
		 */
		if (diff > 300) {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->socks_mask = 0;
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE2;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE2:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send TX1 ping2 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX1].stats.done)
			break;

		priv->state = TST_J1939_AC_CLEANUP;
		break;

	case TST_J1939_AC_CLEANUP:
		for (int i = 0; i < TST_J1939_AC_SOCK_MAX; i++) {
			epoll_ctl(priv->epoll_fd, EPOLL_CTL_DEL,
				  priv->socks[i].fd, NULL);
			close(priv->socks[i].fd);
		}

		*complete = true;
		break;
	default:
		errx(EXIT_FAILURE, "unknown state: %d", priv->state);
		ret1 = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	/* without server all other tests make no sense */
	priv->all_tests_completed = true;
	*complete = true;

	return ret1;
}

/*
 * tst_j1939_ac_test_addr_conflict2 - Test kernel behavior for J1939 address
 *                                    claiming with conflicting priorities,
 *                                    reversed order
 * @priv: Pointer to the tst_j1939_ac_priv structure
 * @complete: Pointer to a boolean flag indicating test completion
 *
 * This function is designed to test the Linux kernel's behavior for the J1939
 * address claiming specification, specifically focusing on the scenario where
 * there is a conflict between low and high priority NAMEs, claimed in reversed
 * order.
 *
 * The test first claims an address with a low priority NAME. It then introduces
 * a conflict against a high priority NAME. In this case, it is expected that
 * the ping with the low priority NAME should not be sent at all, while the
 * pings with the high priority NAME should be sent only after a 250ms delay.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int tst_j1939_ac_test_addr_conflict2(struct tst_j1939_ac_priv *priv,
					    bool *complete)
{
	struct timespec current_time;
	int ret1, ret2;
	int64_t diff;

	clock_gettime(CLOCK_MONOTONIC, &current_time);

	switch (priv->state) {
	case TST_J1939_AC_TEST_START:
		priv->test_start_time = current_time;

		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC1,
				       TST_J1939_AC_NAME1, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX1,
				       TST_J1939_AC_NAME1, J1939_NO_ADDR);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_AC2,
				       TST_J1939_AC_NAME2, TST_J1939_AC_ADDR1);
		tst_j1939_ac_sock_init(priv, TST_J1939_AC_SOCK_TX2,
				       TST_J1939_AC_NAME2, J1939_NO_ADDR);

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC2]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE1;

		break;
	case TST_J1939_AC_WAIT_AC_DONE1:
		if (priv->socks[TST_J1939_AC_SOCK_AC2].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE1;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE1:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR2);
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* after successful address claim, we expect the ping not beeng
		 * send for 250ms.
		 */
		if (ret1 < 0) {
			/* 250ms timeout is expected after the address claim.
			 * add some more milliseconds to not accidentally fail
			 */
			if (diff < 255)
				break;

			errx(EXIT_FAILURE, "send ping1 to socket failed");
		} else if (diff < 245) {
			/* allow some jitter. On some qemu based systems it seems to be needed. */
			errx(EXIT_FAILURE, "send ping1 to socket succeeded too early: %" PRId64,
			     diff);
		} else {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE1;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE1:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send ping1 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX2].stats.done)
			break;

		priv->state = TST_J1939_AC_AC_CLAIM_ADDR2;
		break;
	case TST_J1939_AC_AC_CLAIM_ADDR2:
		priv->test_start_time = current_time;

		/* Claim addresses */
		tst_j1939_ac_claim_addr(&priv->socks[TST_J1939_AC_SOCK_AC1]);
		priv->state = TST_J1939_AC_WAIT_AC_DONE2;

		break;
	case TST_J1939_AC_WAIT_AC_DONE2:
		if (priv->socks[TST_J1939_AC_SOCK_AC1].stats.done) {
			priv->state = TST_J1939_AC_AC_SEND_DONE2;
			priv->test_start_time = current_time;
			break;
		}

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		if (diff >= 250) {
			/* It took too long until packets were sent to the BUS */
			ret1 = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case TST_J1939_AC_AC_SEND_DONE2:
		ret1 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX1],
				       TST_J1939_AC_ADDR2);
		if (!ret1)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX1);
		ret2 = tst_j1939_ac_send_ping(&priv->socks[TST_J1939_AC_SOCK_TX2],
				       TST_J1939_AC_ADDR1);
		if (!ret2)
			priv->socks_mask |= (1 << TST_J1939_AC_SOCK_TX2);

		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);

		/* TX1 should be able to send ping only after 250ms. TX2 should
		 * not be able to send ping at all even after 250ms.
		 */
		if (!ret2)
			errx(EXIT_FAILURE, "ping for TX2 should fail");


		if (!ret1 && diff < 245)
			errx(EXIT_FAILURE, "TX1 ping before 250ms timout should not be posible. diff: %" PRId64,
			     diff);


		/* take extra time to make sure we really are not able to send
		 * any thing at TX2
		 */
		if (diff > 300) {
			/* pings was accepted by sockets, now wait until
			 * they will be send to the bus
			 */
			priv->socks_mask = 0;
			priv->test_start_time = current_time;
			priv->state = TST_J1939_AC_WAIT_PING_DONE2;
		}
		
		break;
	case TST_J1939_AC_WAIT_PING_DONE2:
		diff = tst_j1939_ac_timespec_diff_ms(&current_time,
						     &priv->test_start_time);
		/* 250 msec should be more then enough to passe the packet from
		 * the socket to the bus
		 */
		if (diff >= 250)
			errx(EXIT_FAILURE, "send TX1 ping2 to bus failed");
		if (!priv->socks[TST_J1939_AC_SOCK_TX1].stats.done)
			break;

		priv->state = TST_J1939_AC_CLEANUP;
		break;

	case TST_J1939_AC_CLEANUP:
		for (int i = 0; i < TST_J1939_AC_SOCK_MAX; i++) {
			epoll_ctl(priv->epoll_fd, EPOLL_CTL_DEL,
				  priv->socks[i].fd, NULL);
			close(priv->socks[i].fd);
		}

		*complete = true;
		break;
	default:
		errx(EXIT_FAILURE, "unknown state: %d", priv->state);
		ret1 = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	/* without server all other tests make no sense */
	priv->all_tests_completed = true;
	*complete = true;

	return ret1;
}

struct tst_j1939_ac_cli_test_case test_cases[] = {
	{ tst_j1939_ac_test_250_wait, "One AC with 250 delay for ping" },
	{ tst_j1939_ac_test_second_ac_no_wait, "No delay for ping after second AC" },
	{ tst_j1939_ac_test_addr_conflict1, "Low prion NAME claims addres of high prio NAME" },
	{ tst_j1939_ac_test_addr_conflict2, "High prion NAME claims addres of low prio NAME" },
};

/*
 * tst_j1939_ac_run_self_tests: Executes self-test cases for J1939 address
 *				claiming kernel support
 *
 * @param priv: Pointer to a tst_j1939_ac_priv structure containing private data
 *		for the self-tests
 *
 * This function executes a series of self-test cases for the J1939 address
 * claiming. The test cases are defined in the test_cases array. For each test,
 * the function prints the test number and description, then calls the
 * associated test function. If the test function indicates that the test is
 * complete, the function prints the test result (PASSED or FAILED) and moves on
 * to the next test. Once all tests have been completed, the function prints a
 * final message indicating the completion of all tests.
 */
static void tst_j1939_ac_run_self_tests(struct tst_j1939_ac_priv *priv)
{
	if (!priv->all_tests_completed) {
		size_t num_tests = ARRAY_SIZE(test_cases);

		if (priv->current_test < num_tests) {
			struct tst_j1939_ac_cli_test_case *tc =
				&test_cases[priv->current_test];
			bool test_complete = false;
			int ret;

			if (!priv->state) {
				printf("Executing test %zu: %s\n",
				       priv->current_test + 1,
				       tc->test_description);
				priv->state++;
			}

			ret = tc->test_func(priv, &test_complete);

			if (test_complete) {
				printf("Test %zu: %s.\n",
				       priv->current_test + 1,
				       ret ? "FAILED" : "PASSED");
				priv->current_test++;
				priv->state = 0;
			}
		} else {
			printf("All tests completed.\n");
			priv->all_tests_completed = true;
		}
	}
}

/*
 * tst_j1939_ac_scm_opt_stats: Process J1939 optional statistics attributes in
 *			       the provided buffer
 *
 * @param emsg: Pointer to a tst_j1939_ac_err_msg structure containing socket
 *		error, packet status, and timestamp information
 * @param buf: Pointer to the buffer containing optional statistics attributes
 * @param len: Length of the buffer in bytes
 *
 * This function processes the optional J1939 statistics attributes in the
 * provided buffer. Currently, only J1939_NLA_BYTES_ACKED is supported, which
 * represents the number of bytes acknowledged. The function updates the 'send'
 * field of the emsg->stats structure with the value of J1939_NLA_BYTES_ACKED.
 * If an unsupported attribute type is encountered, the function prints a
 * warning message and continues processing the buffer.
 */
static void tst_j1939_ac_scm_opt_stats(struct tst_j1939_ac_err_msg *emsg,
                                       void *buf, int len) {
        struct tst_j1939_ac_stats *stats = emsg->stats;
        int offset = 0;

        while (offset < len) {
		struct nlattr *nla = (struct nlattr *) ((char *)buf + offset);

		switch (nla->nla_type) {
		case J1939_NLA_BYTES_ACKED:
			stats->send = *(uint32_t *)((char *)nla + NLA_HDRLEN);
			break;
		default:
			warnx("not supported J1939_NLA field\n");
		}

		offset += NLA_ALIGN(nla->nla_len);
	}
}

/*
 * tst_j1939_ac_extract_serr: Extract socket error and packet status information
 *			      from the provided tst_j1939_ac_err_msg structure
 *
 * @param emsg: Pointer to a tst_j1939_ac_err_msg structure containing socket
 *		error, packet status, and timestamp information
 *
 * This function processes the socket error and packet status information
 * contained in the provided tst_j1939_ac_err_msg structure.
 * If the origin is SO_EE_ORIGIN_TIMESTAMPING, it handles the TX scheduling and
 * TX completion events.
 * If the origin is SO_EE_ORIGIN_LOCAL, it handles the TX abort event and
 * prints an error message with the error reason.
 * If the origin is not recognized, it prints a warning message and returns 0.
 * The function returns the error number if an error is encountered, -EINTR for
 * a TX scheduling event, or 0 for other cases.
 */
static int tst_j1939_ac_extract_serr(struct tst_j1939_ac_err_msg *emsg)
{
	struct tst_j1939_ac_stats *stats = emsg->stats;
	struct sock_extended_err *serr = emsg->serr;
	struct scm_timestamping *tss = emsg->tss;

	switch (serr->ee_origin) {
	case SO_EE_ORIGIN_TIMESTAMPING:
		/*
		 * We expect here following patterns:
		 *   serr->ee_info == SCM_TSTAMP_ACK
		 *     Activated with SOF_TIMESTAMPING_TX_ACK
		 * or
		 *   serr->ee_info == SCM_TSTAMP_SCHED
		 *     Activated with SOF_TIMESTAMPING_SCHED
		 * and
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 * the serr->ee_errno should be ENOMSG
		 */
		if (serr->ee_errno != ENOMSG)
			warnx("serr: expected ENOMSG, got: %i",
			      serr->ee_errno);

		if (serr->ee_info == SCM_TSTAMP_SCHED) {
			stats->tskey_sch = serr->ee_data;
			stats->tx_schd_time = tss->ts[0];
		} else {
		 	stats->tskey_ack = serr->ee_data;
		 	stats->done = true;
			stats->err = 0;
			stats->tx_done_time = tss->ts[0];
		}

		if (serr->ee_info == SCM_TSTAMP_SCHED)
			return -EINTR;
		else
			return 0;
	case SO_EE_ORIGIN_LOCAL:
		/*
		 * The serr->ee_origin == SO_EE_ORIGIN_LOCAL is
		 * currently used to notify about locally
		 * detected protocol/stack errors.
		 * Following patterns are expected:
		 *   serr->ee_info == J1939_EE_INFO_TX_ABORT
		 *     is used to notify about session TX
		 *     abort.
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 *   serr->ee_errno == actual error reason
		 *     error reason is converted from J1939
		 *     abort to linux error name space.
		 */
		if (serr->ee_info != J1939_EE_INFO_TX_ABORT)
			warnx("serr: unknown ee_info: %i",
			      serr->ee_info);

		stats->err = -1;
		stats->done = true;
		stats->tx_done_time = tss->ts[0];

		warnx("serr: tx error: %i, %s", serr->ee_errno,
		      strerror(serr->ee_errno));

		return serr->ee_errno;
	default:
		warnx("serr: wrong origin: %u", serr->ee_origin);
	}

	return 0;
}

/*
 * tst_j1939_ac_parse_cm: Parse the control message header to extract socket
 *			  error, packet status, and timestamp information
 *
 * @param emsg: Pointer to a tst_j1939_ac_err_msg structure to store extracted
 *		error messages, packet status, and timestamp information
 * @param cm: Pointer to a cmsghdr structure containing the control message
 *	      header to be parsed
 *
 * This function processes the provided control message header to extract socket
 * error, packet status, and timestamp information.
 * If the control message is of type SCM_TIMESTAMPING, it extracts the
 * timestamp information and stores it in the tst_j1939_ac_err_msg structure.
 * If the control message is of type SCM_TIMESTAMPING_OPT_STATS, it processes
 * and extracts the packet status information.
 * If the control message is of type SCM_J1939_ERRQUEUE, it extracts the socket
 * error information and stores it in the tst_j1939_ac_err_msg structure.
 * If the control message type is not supported, it prints a warning message.
 * The function returns 0 after processing the control message header.
 */
static int tst_j1939_ac_parse_cm(struct tst_j1939_ac_err_msg *emsg,
			     struct cmsghdr *cm)
{
	const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));

	if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
		emsg->tss = (void *)CMSG_DATA(cm);
	} else if (cm->cmsg_level == SOL_SOCKET &&
		   cm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS) {
		void *jstats = (void *)CMSG_DATA(cm);

		/* Activated with SOF_TIMESTAMPING_OPT_STATS */
		tst_j1939_ac_scm_opt_stats(emsg, jstats,
					   cm->cmsg_len - hdr_len);
	} else if (cm->cmsg_level == SOL_CAN_J1939 &&
		   cm->cmsg_type == SCM_J1939_ERRQUEUE) {
		emsg->serr = (void *)CMSG_DATA(cm);
	} else
		warnx("serr: not supported type: %d.%d",
		      cm->cmsg_level, cm->cmsg_type);

	return 0;
}

/*
 * tst_j1939_ac_recv_err: Receive error messages, status of egress and ingress
 *			  packets, and timestamp information from the socket
 *			  error queue.
 *
 * @param sock: The socket file descriptor from which to receive error messages
 *		and packet status
 * @param emsg: Pointer to a tst_j1939_ac_err_msg structure to store received
 *		error messages, packet status, and timestamp information
 *
 * This function receives error messages, status of egress and ingress packets,
 * and timestamp information from the specified socket's error queue using
 * recvmsg with the MSG_ERRQUEUE flag. On failure, it exits with an error
 * message. It then processes the received control messages, populating the
 * provided tst_j1939_ac_err_msg structure with socket error, packet status, and
 * timestamp information. If both socket error and timestamp are found, it
 * extracts the socket error and returns the result. Otherwise, it returns 0.
 */
static int tst_j1939_ac_recv_err(int sock, struct tst_j1939_ac_err_msg *emsg)
{
	char control[200];
	struct cmsghdr *cm;
	int ret;
	struct msghdr msg = {
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};

	ret = recvmsg(sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (ret == -1)
		err(EXIT_FAILURE, "recvmsg error notification");

	if (msg.msg_flags & MSG_CTRUNC)
		errx(EXIT_FAILURE, "recvmsg error notification: truncated");

	emsg->serr = NULL;
	emsg->tss = NULL;

	for (cm = CMSG_FIRSTHDR(&msg); cm && cm->cmsg_len;
	     cm = CMSG_NXTHDR(&msg, cm)) {
		tst_j1939_ac_parse_cm(emsg, cm);
		if (emsg->serr && emsg->tss)
			return tst_j1939_ac_extract_serr(emsg);
	}

	return 0;
}

/*
 * tst_j1939_ac_prepare_for_events: Wait for events on the epoll file descriptor
 *				    and update the number of file descriptors
 *				    with events.
 *
 * @param priv: Pointer to the tst_j1939_ac_priv structure holding test setup
 *		and state information
 * @param nfds: Pointer to an integer that will be updated with the number of
 *		file descriptors with events
 *
 * This function uses epoll_wait to wait for events on the provided epoll file
 * descriptor. If successful, the nfds parameter is updated with the number of
 * file descriptors with events. In case of an error, the function exits with an
 * error message, except for the EINTR error, which is ignored.
 *
 * Returns: 0 on success, does not return on error
 */
static int tst_j1939_ac_prepare_for_events(struct tst_j1939_ac_priv *priv,
					   int *nfds)
{
	int ret;

	ret = epoll_wait(priv->epoll_fd, priv->epoll_events,
		         priv->epoll_events_size, 0);
	if (ret < 0) {
		if (errno != EINTR)
			err(EXIT_FAILURE, "epoll_wait failed");
	}

	*nfds = ret;

	return 0;
}

/*
 * tst_j1939_ac_handle_events: Process events on sockets for which epoll_wait
 *			       has reported events
 *
 * @param priv: Pointer to the tst_j1939_ac_priv structure holding test setup
 *		and state information
 * @param nfds: Number of file descriptors with events reported by epoll_wait
 *
 * This function iterates through the epoll events reported by epoll_wait and
 * processes the events for each socket. If an EPOLLERR event is detected, it
 * calls tst_j1939_ac_recv_err to handle the "error message", which is used to
 * communicate not only errors, but also different state information about the
 * status of egress or ingress packets, as well as timestamps related to these
 * states (e.g., the actual transmission time to the CAN bus). If
 * tst_j1939_ac_recv_err returns an error other than EINTR, the function returns
 * the error code. Otherwise, it continues processing events.
 *
 * Returns: 0 on success, error code on failure
 */
static int tst_j1939_ac_handle_events(struct tst_j1939_ac_priv *priv,
                                      int nfds) {
        int ret;
        int n;

        for (n = 0; n < nfds && n < priv->epoll_events_size; ++n) {
		struct epoll_event *ev = &priv->epoll_events[n];
		struct tst_j1939_ac_sock *sock = ev->data.ptr;

		if (!sock) {
			warn("no sock");
			continue;
		}

		if (!ev->events) {
			warn("no events");
			continue;
		}

		if (ev->events & EPOLLERR) {
			struct tst_j1939_ac_err_msg emsg = {
				.stats = &sock->stats,
			};

			ret = tst_j1939_ac_recv_err(sock->fd, &emsg);
			if (ret && ret != -EINTR)
				return ret;
		}
	}

	return 0;
}

/*
 * tst_j1939_ac_process_events_and_tasks: Process events reported by epoll_wait
 *					  and run self-tests
 *
 * @param priv: Pointer to the tst_j1939_ac_priv structure holding test setup
 * and state information
 *
 * This function prepares for events by calling tst_j1939_ac_prepare_for_events
 * and provides the number of file descriptors with reported events (nfds). If
 * any events are reported, it calls tst_j1939_ac_handle_events to process the
 * events. The function then calls tst_j1939_ac_run_self_tests to run the
 * self-tests.
 *
 * Returns: 0 on success, error code on failure
 */
static int tst_j1939_ac_process_events_and_tasks(struct tst_j1939_ac_priv *priv)
{
	int nfds = 0;
	int ret;

	ret = tst_j1939_ac_prepare_for_events(priv, &nfds);
	if (ret)
		return ret;

	if (nfds > 0) {
		ret = tst_j1939_ac_handle_events(priv, nfds);
		if (ret)
			return ret;
	}

	tst_j1939_ac_run_self_tests(priv);

	return 0; 
}

/*
 * tst_j1939_ac_epoll_prepare: Initialize epoll instance for the given private
 *			       test structure
 *
 * @param priv: Pointer to the tst_j1939_ac_priv structure holding test setup
 *		and state information
 *
 * This function initializes an epoll instance for the given private test
 * structure by calling epoll_create1. On failure, it exits with an error
 * message. It also sets the epoll_events_size based on the size of the
 * epoll_events array.
 */
static void tst_j1939_ac_epoll_prepare(struct tst_j1939_ac_priv *priv) {
        priv->epoll_fd = epoll_create1(0);
        if (priv->epoll_fd < 0)
                err(EXIT_FAILURE, "epoll_create1");

        priv->epoll_events_size = ARRAY_SIZE(priv->epoll_events);
}

static void tst_j1939_ac_print_help(void)
{
	printf("An SAE J1939 Address Claiming test for linux kernel J1939 stack.\n");
	printf("\nUsage: tst-j1939-ac [options]\n");
	printf("\nOptions:\n");
	printf(" -i, --interface <interface>	CAN interface name (default vcan0)\n");
	printf(" -h, --help			Print this help and exit\n");
	printf("\nExamples:\n");
	printf("tst-j1939-ac\n	(execute supported tests on interface vcan0)\n");
	printf("tst-j1939-ac -i can0\n	(execute supported tests on interface can0)\n");
	printf("\nReport bugs to <linux-can@vger.kernel.org>\n");
}

static int tst_j1939_ac_parse_args(struct tst_j1939_ac_priv *priv, int argc,
				   char *argv[])
{
	bool interface_set = false;
	int long_index = 0;
	int opt;

	static struct option long_options[] = {
		{"interface", required_argument, 0, 'i'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "?ha:n:r:m:i:l:", long_options,
				  &long_index)) != -1) {
		switch (opt) {
		case 'i':
			priv->can_ifindex = if_nametoindex(optarg);
			if (!priv->can_ifindex) {
				err(EXIT_FAILURE, "Interface %s not found\n",
				    optarg);
			}
			interface_set = true;
			break;
		default:
			tst_j1939_ac_print_help();
			return -EINVAL;
		}
	}

	if (!interface_set) {
		const char *name = TST_J1939_AC_DEFAULT_INTERFACE;

		printf("interface is not specified. Trying default one: %s\n",
		       name);
		priv->can_ifindex = if_nametoindex(name);
		if (!priv->can_ifindex)
			err(EXIT_FAILURE, "Interface %s not found.\n",
			    name);

	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct tst_j1939_ac_priv priv[1] = { 0 };
	int ret;

	ret = tst_j1939_ac_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	tst_j1939_ac_epoll_prepare(priv);

	while (!priv->all_tests_completed) {
		ret = tst_j1939_ac_process_events_and_tasks(priv);
		if (ret)
			break;
	}

	return ret;
}
