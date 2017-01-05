/* evaluate MSG_ZEROCOPY over the loopback interface */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <limits.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MSG_ZEROCOPY	0x4000000

#define NUM_LOOPS	4	/* MUST BE > 1 for corking to work */
#define TXC_FUDGE	100

static int  cfg_len_ms		= 4200;
static int  cfg_report_len_ms	= 1000;
static int  cfg_payload_len	= ((1 << 16) - 100);
static bool cfg_test_packet;
static bool cfg_test_raw;
static bool cfg_test_raw_hdrincl;
static bool cfg_test_tcp;
static bool cfg_test_udp;
static bool cfg_test_udp_cork;
static bool cfg_verbose;
static bool cfg_zerocopy;

static bool flag_cork;

static uint64_t tstop, treport;

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static uint16_t get_ip_csum(const uint16_t *start, int num_words)
{
	unsigned long sum = 0;
	int i;

	for (i = 0; i < num_words; i++)
		sum += start[i];

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static void timer_start(int timeout_ms)
{
	uint64_t tstart;

	tstart = gettimeofday_ms();
	treport = tstart + cfg_report_len_ms;
	tstop = tstart + timeout_ms;
}

static bool timer_report(void)
{
	uint64_t tstart;

	tstart = gettimeofday_ms();
	if (tstart < treport)
		return false;

	treport = tstart + cfg_report_len_ms;
	return true;
}

static bool timer_stop(void)
{
	return gettimeofday_ms() > tstop;
}

static int getnumcpus(void)
{
	int num = sysconf(_SC_NPROCESSORS_ONLN);

	if (num < 1)
		error(1, 0, "get num cpus\n");
	return num;
}

static int setcpu(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask)) {
		fprintf(stderr, "setaffinity %d\n", cpu);
		return 1;
	}

	return 0;
}

static void test_mtu_is_max(int fd)
{
	struct ifreq ifr = {
		.ifr_name = "lo",
	};

	if (ioctl(fd, SIOCGIFMTU, &ifr))
		error(1, errno, "ioctl get mtu");

	if (ifr.ifr_mtu != 1 << 16)
		error(1, 0, "mtu=%u expected=2^16\n", ifr.ifr_mtu);
}

static void do_poll(int fd, int dir)
{
	struct pollfd pfd;
	int ret;

	pfd.events = dir;
	pfd.revents = 0;
	pfd.fd = fd;

	ret = poll(&pfd, 1, 10);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		error(1, 0, "poll: EAGAIN");
}

static bool do_write_once(int fd, struct msghdr *msg, int total_len, bool zcopy)
{
	int ret, flags;

	flags = MSG_DONTWAIT;
	if (zcopy)
		flags |= MSG_ZEROCOPY;

	ret = sendmsg(fd, msg, flags);
	if (ret == -1 && (errno == EAGAIN || errno == ENOBUFS))
		return false;

	if (ret == -1)
		error(1, errno, "send");
	if (ret != total_len)
		error(1, 0, "send: ret=%u\n", ret);

	return true;
}

static void do_print_data_mismatch(char *tx, char *rx, int len)
{
	int i;

	fprintf(stderr, "tx: ");
	for (i = 0; i < len; i++)
		fprintf(stderr, "%hx ", tx[i] & 0xff);
	fprintf(stderr, "\nrx: ");
	for (i = 0; i < len; i++)
		fprintf(stderr, "%hx ", rx[i] & 0xff);
	fprintf(stderr, "\n");
}

/* Flush @remaining bytes from the socket, blocking if necessary */
static void do_flush_tcp(int fd, long remaining)
{
	unsigned long tstop;
	int ret;

	tstop = gettimeofday_ms() + 500;
	while (remaining > 0 && gettimeofday_ms() < tstop) {
		ret = recv(fd, NULL, remaining, MSG_TRUNC);
		if (ret == -1)
			error(1, errno, "recv (flush)");
		remaining -= ret;
		if (!remaining)
			return;
		fprintf(stderr, "recv (flush): %dB, %ldB left\n",
			ret, remaining);
	}

	error(1, 0, "recv (flush): %ldB at timeout", remaining);
}

static bool do_read_once(int fd, char *tbuf, int type, bool corked, long *bytes)
{
	char rbuf[32], *payload;
	int ret, len, expected, flags;

	flags = MSG_DONTWAIT;
	/* MSG_TRUNC differs on SOCK_STREAM: it flushes the buffer */
	if (type != SOCK_STREAM)
		flags |= MSG_TRUNC;

	ret = recv(fd, rbuf, sizeof(rbuf), flags);
	if (ret == -1 && errno == EAGAIN)
		return false;
	if (ret == -1)
		error(1, errno, "recv");
	if (type == SOCK_RAW)
		ret -= sizeof(struct iphdr);

	expected = sizeof(rbuf);
	if (flags & MSG_TRUNC) {
		expected = cfg_payload_len;
		if (corked)
			expected *= NUM_LOOPS;
		*bytes += expected;
	} else {
		*bytes += cfg_payload_len;
	}
	if (ret != expected)
		error(1, 0, "recv: ret=%u (exp=%u)\n", ret, expected);

	payload = rbuf;
	len = sizeof(rbuf);
	if (type == SOCK_RAW) {
		payload += sizeof(struct iphdr);
		len -= sizeof(struct iphdr);
	}

	if (memcmp(payload, tbuf, len)) {
		do_print_data_mismatch(tbuf, payload, len);
		error(1, 0, "\nrecv: data mismatch\n");
	}

	/* Stream sockets are not truncated, so flush explicitly */
	if (type == SOCK_STREAM)
		do_flush_tcp(fd, cfg_payload_len - sizeof(rbuf));

	return true;
}

static void setup_iph(struct iphdr *iph, uint16_t payload_len)
{
	memset(iph, 0, sizeof(*iph));
	iph->version	= 4;
	iph->tos	= 0;
	iph->ihl	= 5;
	iph->ttl	= 8;
	iph->saddr	= htonl(INADDR_LOOPBACK);
	iph->daddr	= htonl(INADDR_LOOPBACK);
	iph->protocol	= IPPROTO_EGP;
	iph->tot_len	= htons(sizeof(*iph) + payload_len);
	iph->check	= get_ip_csum((void *) iph, iph->ihl << 1);
	/* No need to calculate checksum: set by kernel */
}

static void do_cork(int fd, bool enable)
{
	int cork = !!enable;

	if (setsockopt(fd, IPPROTO_UDP, UDP_CORK, &cork, sizeof(cork)))
		error(1, errno, "cork %u", enable);
}

static int do_read_notification(int fd)
{
	struct sock_extended_err *serr;
	struct cmsghdr *cm;
	struct msghdr msg = {};
	char control[100];
	int64_t hi, lo, range;
	int ret;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_ERRQUEUE);
	if (ret == -1 && errno == EAGAIN)
		return 0;

	if (ret == -1)
		error(1, errno, "recvmsg notification");
	if (msg.msg_flags & MSG_CTRUNC)
		error(1, errno, "recvmsg notification: truncated");

	cm = CMSG_FIRSTHDR(&msg);
	if (!cm)
		error(1, 0, "cmsg: no cmsg");
	if (!((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
	      (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR) ||
	      (cm->cmsg_level == SOL_PACKET && cm->cmsg_type == PACKET_TX_TIMESTAMP)))
		error(1, 0, "serr: wrong type");

	serr = (void *) CMSG_DATA(cm);
	if (serr->ee_errno != 0 || serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY)
		error(1, 0, "serr: wrong type");

	hi = serr->ee_data;
	lo = serr->ee_info;
	range = hi - lo + 1;
	if (range < 0)
		range += UINT32_MAX;

	if (cfg_verbose)
		fprintf(stderr, "completed: %lu (h=%lu l=%lu)\n",
			range, hi, lo);

	return (int) range;
}

static int do_read_notifications(int fd)
{
	int ret, len = 0;

	do {
		ret = do_read_notification(fd);
		len += ret;
	} while (ret);

	return len;
}

static void do_run(int fdt, int fdr, int domain, int type, int protocol)
{
	static char tbuf[1 << 16];
	struct sockaddr_ll laddr;
	struct msghdr msg;
	struct iovec iov[2];
	struct iphdr iph;
	long numtx = 0, numrx = 0, bytesrx = 0, numtxc = 0, expected_txc = 0;
	int cpu, i, total_len = 0, type_r = type;

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	for (i = 0; i < sizeof(tbuf); i++)
		tbuf[i] = 'a' + (i % 26);

	i = 0;

	/* for packet sockets, must prepare link layer information */
	if (domain == PF_PACKET) {
		memset(&laddr, 0, sizeof(laddr));
		laddr.sll_family	= AF_PACKET;
		laddr.sll_ifindex	= 1;	/* lo */
		laddr.sll_protocol	= htons(ETH_P_IP);
		laddr.sll_halen		= ETH_ALEN;

		msg.msg_name		= &laddr;
		msg.msg_namelen		= sizeof(laddr);

		/* with PF_PACKET tx, do not expect ip_hdr on Rx */
		type_r			= SOCK_DGRAM;
	}

	if (domain == PF_PACKET || protocol == IPPROTO_RAW) {
		setup_iph(&iph, cfg_payload_len);
		iov[i].iov_base = (void *) &iph;
		iov[i].iov_len = sizeof(iph);
		total_len += iov[i].iov_len;
		i++;
	}
	iov[i].iov_base = tbuf;
	iov[i].iov_len = cfg_payload_len;
	total_len += iov[i].iov_len;

	msg.msg_iovlen = i + 1;
	msg.msg_iov = iov;

	cpu = getnumcpus() - 1;
	setcpu(cpu);
	fprintf(stderr, "cpu: %u\n", cpu);

	do {
		if (cfg_zerocopy)
			numtxc += do_read_notifications(fdt);

		if (flag_cork)
			do_cork(fdt, true);

		for (i = 0; i < NUM_LOOPS; i++) {
			bool do_zcopy = cfg_zerocopy;

			if (flag_cork && (i & 0x1))
				do_zcopy = false;

			if (!do_write_once(fdt, &msg, total_len, do_zcopy)) {
				do_poll(fdt, POLLOUT);
				break;
			}

			numtx++;
			if (do_zcopy)
				expected_txc++;
		}
		if (flag_cork)
			do_cork(fdt, false);

		while (do_read_once(fdr, tbuf, type_r, flag_cork, &bytesrx))
			numrx++;

		if (timer_report()) {
			fprintf(stderr, "rx=%lu (%lu MB) tx=%lu txc=%lu\n",
				numrx, bytesrx >> 20, numtx, numtxc);
		}
	} while (!timer_stop());

	if (cfg_zerocopy)
		numtxc += do_read_notifications(fdt);

	if (flag_cork)
		numtx /= NUM_LOOPS;

	if (labs(numtx - numrx) > TXC_FUDGE)
		error(1, 0, "missing packets: %lu != %lu\n", numrx, numtx);
	if (cfg_zerocopy && labs(expected_txc - numtxc) > TXC_FUDGE)
		error(1, 0, "missing completions: rx=%lu expected=%lu\n",
			    numtxc, expected_txc);
}

static int do_setup_rx(int domain, int type, int protocol)
{
	int fdr;

	if (domain == PF_PACKET) {
		/* Even when testing PF_PACKET Tx, Rx on PF_INET */
		domain = PF_INET;
		type = SOCK_RAW;
		protocol = IPPROTO_EGP;
	} else if (protocol == IPPROTO_RAW) {
		protocol = IPPROTO_EGP;
	}

	fdr = socket(domain, type, protocol);
	if (fdr == -1)
		error(1, errno, "socket r");

	return fdr;
}

static void do_setup_and_run(int domain, int type, int protocol)
{
	struct sockaddr_in addr;
	socklen_t alen;
	int fdr, fdt, ret;

	fprintf(stderr, "test socket(%u, %u, %u)\n", domain, type, protocol);

	fdr = do_setup_rx(domain, type, protocol);
	fdt = socket(domain, type, protocol);
	if (fdt == -1)
		error(1, errno, "socket t");

	test_mtu_is_max(fdr);

	if (domain != PF_PACKET) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		alen = sizeof(addr);

		if (bind(fdr, (void *) &addr, sizeof(addr)))
			error(1, errno, "bind");
		if (type == SOCK_STREAM && listen(fdr, 1))
			error(1, errno, "listen");
		if (getsockname(fdr, (void *) &addr, &alen) ||
		    alen != sizeof(addr))
			error(1, 0, "getsockname");
		if (connect(fdt, (void *) &addr, sizeof(addr)))
			error(1, errno, "connect");
	}

	if (type == SOCK_STREAM) {
		int fda = fdr;

		fdr = accept(fda, NULL, NULL);
		if (fdr == -1)
			error(1, errno, "accept");
		if (close(fda))
			error(1, errno, "close listen sock");
	}

	ret = 1 << 21;
	if (setsockopt(fdr, SOL_SOCKET, SO_RCVBUF, &ret, sizeof(ret)))
		error(1, errno, "socklen r");
	if (setsockopt(fdt, SOL_SOCKET, SO_SNDBUF, &ret, sizeof(ret)))
		error(1, errno, "socklen t");

	timer_start(cfg_len_ms);
	do_run(fdt, fdr, domain, type, protocol);

	if (close(fdt))
		error(1, errno, "close t");
	if (close(fdr))
		error(1, errno, "close r");

}

static void parse_opts(int argc, char **argv)
{
	const char on[] = "ON", off[] = "OFF";
	const int max_payload = IP_MAXPACKET - sizeof(struct iphdr);
	int c;

	while ((c = getopt(argc, argv, "l:prRs:tuUvz")) != -1) {
		switch (c) {
		case 'l':
			cfg_len_ms = strtoul(optarg, NULL, 10) * 1000;
			break;
		case 'p':
			cfg_test_packet = true;
			break;
		case 'r':
			cfg_test_raw = true;
			break;
		case 'R':
			cfg_test_raw_hdrincl = true;
			break;
		case 's':
			cfg_payload_len = strtoul(optarg, NULL, 0);
			break;
		case 't':
			cfg_test_tcp = true;
			break;
		case 'u':
			cfg_test_udp = true;
			break;
		case 'U':
			cfg_test_udp_cork = true;
			break;
		case 'v':
			cfg_verbose = true;
			break;
		case 'z':
			cfg_zerocopy = true;
			break;
		}
	}

	if (cfg_payload_len > max_payload)
		error(1, 0, "-s: payload too long");
	if (cfg_payload_len >= (max_payload - sizeof(struct tcphdr) - 10))
		fprintf(stderr, "warn: len may exceed limit\n");

	if (cfg_verbose) {
		fprintf(stderr, "time:     %u ms\n"
				"size:     %u B\n"
				"zerocopy: %s\n",
			cfg_len_ms,
			cfg_payload_len,
			cfg_zerocopy ? on : off);
	}
}

int main(int argc, char **argv)
{
	parse_opts(argc, argv);

	if (cfg_test_packet)
		do_setup_and_run(PF_PACKET, SOCK_DGRAM, 0);
	if (cfg_test_udp)
		do_setup_and_run(PF_INET, SOCK_DGRAM, 0);
	if (cfg_test_udp_cork) {
		int saved_payload_len = cfg_payload_len;

		cfg_payload_len /= NUM_LOOPS;

		flag_cork = true;
		do_setup_and_run(PF_INET, SOCK_DGRAM, 0);
		flag_cork = false;

		cfg_payload_len = saved_payload_len;
	}
	if (cfg_test_raw)
		do_setup_and_run(PF_INET, SOCK_RAW, IPPROTO_EGP);
	if (cfg_test_raw_hdrincl)
		do_setup_and_run(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (cfg_test_tcp)
		do_setup_and_run(PF_INET, SOCK_STREAM, 0);

	fprintf(stderr, "OK. All tests passed\n");
	return 0;
}
