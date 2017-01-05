#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <limits.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MSG_ZEROCOPY	0x4000000

#define SK_FUDGE_FACTOR	2		/* allow for overhead in SNDBUF */
#define BUFLEN		(400 * 1000)	/* max length of send call */
#define DEST_PORT	9000

uint32_t sent = UINT32_MAX, acked = UINT32_MAX;

int cfg_batch_notify = 10;
int cfg_num_runs = 16;
size_t cfg_socksize = 1 << 20;
int cfg_stress_sec;
int cfg_verbose;
bool cfg_zerocopy;

static unsigned long gettime_now_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static void do_set_socksize(int fd)
{
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE,
		       &cfg_socksize, sizeof(cfg_socksize)))
		error(1, 0, "setsockopt sndbufforce");

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE,
		       &cfg_socksize, sizeof(cfg_socksize)))
		error(1, 0, "setsockopt sndbufforce");
}

static bool do_read_notification(int fd)
{
	struct sock_extended_err *serr;
	struct cmsghdr *cm;
	struct msghdr msg = {};
	char control[100];
	int64_t hi, lo;
	int ret;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_ERRQUEUE);
	if (ret == -1 && errno == EAGAIN)
		return false;
	if (ret == -1)
		error(1, errno, "recvmsg notification");
	if (msg.msg_flags & MSG_CTRUNC)
		error(1, errno, "recvmsg notification: truncated");

	cm = CMSG_FIRSTHDR(&msg);
	if (!cm || cm->cmsg_level != SOL_IP ||
	    (cm->cmsg_type != IP_RECVERR && cm->cmsg_type != IPV6_RECVERR))
		error(1, 0, "cmsg: wrong type");

	serr = (void *) CMSG_DATA(cm);
	if (serr->ee_errno != 0 || serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY)
		error(1, 0, "serr: wrong type");

	hi = serr->ee_data;
	lo = serr->ee_info;
	if (lo != (uint32_t) (acked + 1))
		error(1, 0, "notify: %lu..%lu, expected %u\n",
		      lo, hi, acked + 1);
	acked = hi;

	if (cfg_verbose)
		fprintf(stderr, "completed: %lu..%lu\n", lo, hi);

	return true;
}

static void do_poll(int fd, int events, int timeout)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;

	ret = poll(&pfd, 1, timeout);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret != 1)
		error(1, 0, "poll timeout. events=0x%x acked=%u sent=%u",
		      pfd.events, acked, sent);

	if (cfg_verbose >= 2)
		fprintf(stderr, "poll ok. events=0x%x revents=0x%x\n",
			pfd.events, pfd.revents);
}

static void do_send(int fd, int len, int flags)
{
	static char data[BUFLEN];
	struct msghdr msg = {};
	struct iovec iov = {};
	int ret;

	if (len > BUFLEN)
		error(1, 0, "write out of bounds");

	iov.iov_base = data;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(fd, &msg, flags);
	if (ret == -1)
		error(1, errno, "sendmsg");
	if (ret != len)
		error(1, errno, "sendmsg: %u < %u", ret, len);

	if (cfg_verbose >= 2)
		fprintf(stderr, "  sent %6u B\n", len);

	if (flags & MSG_ZEROCOPY && len) {
		sent++;
		if (cfg_verbose)
			fprintf(stderr, "    add %u\n", sent);
		do_read_notification(fd);
	}
}

/* wait for all outstanding notifications to arrive */
static void wait_for_notifications(int fd)
{
	unsigned long tstop, tnow;

	if (acked == sent)
		return;

	tnow = gettime_now_ms();
	tstop = tnow + 10000;
	do {
		do_poll(fd, 0 /* POLLERR is always reported */, tstop - tnow);

		while (do_read_notification(fd)) {}
		if (acked == sent)
			return;

		tnow = gettime_now_ms();
	} while (tnow < tstop);

	error(1, 0, "notify timeout. acked=%u sent=%u", acked, sent);
}

static void run_test(int fd, int len_cp, int len_zc, int batch)
{
	int i;

	fprintf(stderr, "\ncp=%u zc=%u batch=%u\n", len_cp, len_zc, batch);

	if (acked != sent)
		error(1, 0, "not empty when expected");

	if (batch * BUFLEN * SK_FUDGE_FACTOR > cfg_socksize) {
		batch = cfg_socksize / BUFLEN / SK_FUDGE_FACTOR;
		if (!batch)
			error(1, 0, "cannot batch: increase socksize ('-s')");
	}

	for (i = 0; i < cfg_num_runs; i++) {
		if (len_cp) {
			do_poll(fd, POLLOUT, 1000);
			do_send(fd, len_cp, 0);
		}

		do_poll(fd, POLLOUT, 1000);
		do_send(fd, len_zc, cfg_zerocopy ? MSG_ZEROCOPY : 0);

		if (i % batch == 0)
			wait_for_notifications(fd);
	}

	wait_for_notifications(fd);
}

static void run_single(int fd, int len, int batch)
{
	run_test(fd, 0, len, batch);
}

/* combine zerocopy fragments with regular fragments */
static void run_mix_zerocopy(int fd, int len_cp, int len_zc)
{
	run_test(fd, len_cp, len_zc, 1);
}

static void run_tests(int fd)
{
	/* test basic use */
	run_single(fd, 4096, 1);
	run_single(fd, 1500, 1);
	run_single(fd, 1472, 1);
	run_single(fd, 32000, 1);
	run_single(fd, 65000, 1);
	run_single(fd, BUFLEN, 1);

	/* test notification on copybreak: data fits in skb head, no frags */
	run_single(fd, 1, 1);

	/* test coalescing */
	run_single(fd, 32000, 4);
	run_single(fd, 3000, 10);
	run_single(fd, 100, 100);

	run_mix_zerocopy(fd, 2000, 2000);
	run_mix_zerocopy(fd, 100, 100);
	run_mix_zerocopy(fd, 100, 1500);	/* fits coalesce in skb head */
	run_mix_zerocopy(fd, 100, BUFLEN - 100);
	run_mix_zerocopy(fd, 2000, 2000);

	run_mix_zerocopy(fd, 1000, 12000);
	run_mix_zerocopy(fd, 12000, 1000);
	run_mix_zerocopy(fd, 12000, 12000);
	run_mix_zerocopy(fd, 16000, 16000);

	/* test more realistic async notifications */
	run_single(fd, 1472, cfg_batch_notify);
	run_single(fd, 1, cfg_batch_notify);
	run_single(fd, BUFLEN, cfg_batch_notify);
}

static void run_stress_test(int fd, int runtime_sec)
{
	const int max_batch = 32;
	unsigned long tstop, i = 0;
	int len, len_cp, batch;

	cfg_socksize = BUFLEN * max_batch * SK_FUDGE_FACTOR;
	do_set_socksize(fd);

	tstop = gettime_now_ms() + (runtime_sec * 1000);
	do {
		len = random() % BUFLEN;

		/* create some skbs with only zerocopy frags */
		if (len && ((i % 200) < 100))
			len_cp = random() % BUFLEN;
		else
			len_cp = 0;

		batch = random() % max_batch;

		fprintf(stderr, "stress: cnt=%lu len_cp=%u len=%u batch=%u\n",
			i, len_cp, len, batch);
		run_test(fd, len_cp, len, batch);

		i++;
	} while (gettime_now_ms() < tstop);
}

static void parse_opts(int argc, char **argv, struct in_addr *addr)
{
	int c;

	addr->s_addr = 0;

	while ((c = getopt(argc, argv, "b:H:n:s:S:vV:z")) != -1) {
		switch (c) {
		case 'b':
			cfg_batch_notify = strtol(optarg, NULL, 0);
			break;
		case 'H':
			if (inet_pton(AF_INET, optarg, addr) != 1)
				error(1, 0, "inet_pton: could not parse host");
			break;
		case 'n':
			cfg_num_runs = strtol(optarg, NULL, 0);
			break;
		case 's':
			cfg_socksize = strtol(optarg, NULL, 0);
			break;
		case 'S':
			cfg_stress_sec = strtol(optarg, NULL, 0);
		case 'v':
			cfg_verbose = 1;
			break;
		case 'V':
			cfg_verbose = strtol(optarg, NULL, 0);
			break;
		case 'z':
			cfg_zerocopy = true;
			break;
		}
	}

	if (addr->s_addr == 0)
		error(1, 0, "host ('-H') argument required");

	if (cfg_verbose) {
		fprintf(stderr, "batch_notify:  %u\n", cfg_batch_notify);
		fprintf(stderr, "num_runs:      %u\n", cfg_num_runs);
		fprintf(stderr, "socksize:      %lu\n", cfg_socksize);
		fprintf(stderr, "stress:        %u\n", cfg_stress_sec);
		fprintf(stderr, "zerocopy:      %s\n", cfg_zerocopy ? "ON" : "OFF");
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr = {};
	int fd;

	parse_opts(argc, argv, &addr.sin_addr);

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	do_set_socksize(fd);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEST_PORT);
	if (connect(fd, (void *) &addr, sizeof(addr)))
		error(1, errno, "connect");

	if (cfg_num_runs)
		run_tests(fd);

	if (cfg_stress_sec)
		run_stress_test(fd, cfg_stress_sec);

	if (close(fd))
		error(1, errno, "close");

	fprintf(stderr, "OK. All tests passed\n");
	return 0;
}
