#include <sys/types.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <paths.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define MINIT_MAX_NETIF 10
#define MINIT_MAX_ROUTE 10
#define KILL_GRACE_TIME 23
#define START_PROG "/etc/minit/start0"

static int Reboot = 0;
static int Alarm = 0;

static void setup_devfs(void);
static void setup_console(void);
static void remount_root();
static void setup_hostname();
static int net_env_kv(const char* fmt, int i, char* first, char** second);
static void setup_network(void);
static void ip4_config(const char* iface, const char* cidr);
static void ip6_config(const char* iface, const char* cidr);
static void route_add(struct sockaddr_storage *so);
static void ip4_route(const char* dst, const char* gw);
static void ip6_route(const char* dst, const char* gw);
static void setup_signal_handlers();
static void handle_signal(int sig);
static void loop_start_prog();
static void kill_all();

int
main(int argc __unused, char** argv __unused)
{
	if (getpid() != 1) return 1; /* no. */

	setsid();
	setlogin("root");
	setup_devfs();
	setup_console();
	remount_root();
	setup_hostname();
	setup_network();
	setup_signal_handlers();
	loop_start_prog();
	sync();
	reboot(Reboot);
}

static void
setup_devfs(void)
{
	struct iovec iov[4];

	char _fstype[] = "fstype";
	char _devfs[] = "devfs";
	char _fspath[] = "fspath";
	char _dev[] = "/dev";

	iov[0].iov_base = _fstype; iov[0].iov_len = sizeof _fstype;
	iov[1].iov_base = _devfs; iov[1].iov_len = sizeof _devfs;
	iov[2].iov_base = _fspath; iov[2].iov_len = sizeof _fspath;
	iov[3].iov_base = _dev; iov[3].iov_len = sizeof _dev;
	nmount(iov, 4, 0);
}

static void
setup_console(void)
{
	int fd;
	int pgrp;
	pgrp = getpgrp();
	close(0);
	close(1);
	close(2);
	fd = open("/dev/console", O_RDWR | O_NONBLOCK);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	ioctl(fd, TIOCSCTTY, (char *)0);
	ioctl(fd, TIOCSPGRP, &pgrp);
	printf ("> setup_console()\n");
}

static void
remount_root()
{
	char kenv_value[512];
	char *dev;
	int b;
	struct iovec iov[16];

	char _sync[] = "sync";
	char _noatime[] = "noatime";
	char _rw[] = "rw";
	char _noro[] = "noro";
	char _update[] = "update";
	char _fstype[] = "fstype";
	char _ufs[] = "ufs";
	char _fspath[] = "fspath";
	char _slash[] = "/";
	char _from[] = "from";

	printf ("> remount_root()\n");

	b = kenv(KENV_GET, "vfs.root.mountfrom", kenv_value,
	    (sizeof kenv_value) -1);
	if (b < 4 || strncmp(kenv_value, "ufs:", 4) != 0) {
		printf("FAILED: kenv\n");
		return;
	}
	dev = kenv_value + 4;

	iov[0].iov_base = _sync; iov[0].iov_len = sizeof _sync;
	iov[1].iov_base = NULL; iov[1].iov_len = 0;
	iov[2].iov_base = _noatime; iov[2].iov_len = sizeof _noatime;
	iov[3].iov_base = NULL; iov[3].iov_len = 0;
	iov[4].iov_base = _rw; iov[4].iov_len = sizeof _rw;
	iov[5].iov_base = NULL; iov[5].iov_len = 0;
	iov[6].iov_base = _noro; iov[6].iov_len = sizeof _noro;
	iov[7].iov_base = NULL; iov[7].iov_len = 0;
	iov[8].iov_base = _update; iov[8].iov_len = sizeof _update;
	iov[9].iov_base = NULL; iov[9].iov_len = 0;
	iov[10].iov_base = _fstype; iov[10].iov_len = sizeof _fstype;
	iov[11].iov_base = _ufs; iov[11].iov_len = sizeof _ufs;
	iov[12].iov_base = _fspath; iov[12].iov_len = sizeof _fspath;
	iov[13].iov_base = _slash; iov[13].iov_len = sizeof _slash;
	iov[14].iov_base = _from; iov[14].iov_len = sizeof _from;
	iov[15].iov_base = dev; iov[15].iov_len = strlen(dev) +1;

	if(nmount(iov, 16, 0) != 0)
		printf("FAILED: nmount (%s)\n", strerror(errno));
}

static void
setup_hostname()
{
	char hn[256];
	int b;
	if ((b = kenv(KENV_GET, "minit.hostname", hn, (sizeof hn) -1)) > 0)
		sethostname((const char*)hn, (size_t)b);
}

static int
net_env_kv(const char* fmt, int i, char* first, char** second)
{
	char kenv_key[256];

	snprintf(kenv_key, (sizeof kenv_key) -1, fmt, i);
	if (kenv(KENV_GET, kenv_key, first, 511)> 0 &&
	    (*second = strchr(first, ' ')) != NULL) {
		**second = 0;
		(*second)++;
		return 1;
	}
	return 0;
}

static void
setup_network(void)
{
	char first[512];
	char *second = NULL;
	int i;

	printf("> setup_network()\n>> ipv4 interfaces\n");

	ip4_config("lo0", "127.0.0.1/8");

	for (i = 0; i < MINIT_MAX_NETIF; i++)
		if (net_env_kv("minit.ip4.iface.%d", i, first, &second))
			ip4_config(first, second);

	printf(">> ipv6 interfaces\n");

	ip6_config("lo0", "::1/128");

	for (i = 0; i < MINIT_MAX_NETIF; i++)
		if (net_env_kv("minit.ip6.iface.%d", i, first, &second))
			ip6_config(first, second);

	printf(">> ipv4 routes\n");

	for (i = 0; i < MINIT_MAX_ROUTE; i++)
		if (net_env_kv("minit.ip4.route.%d", i, first, &second)) {
			if (strcmp(first, "default") == 0)
				ip4_route("0.0.0.0/0", second);
			else ip4_route(first, second);
		}

	printf(">> ipv6 routes\n");

	for (i = 0; i < MINIT_MAX_ROUTE; i++)
		if (net_env_kv("minit.ip6.route.%d", i, first, &second)) {
			if (strcmp(first, "default") == 0)
				ip6_route("::0/0", second);
			else ip6_route(first, second);
		}
}

static void
ip6_config(const char* iface, const char* cidr)
{
	struct in6_aliasreq ifra;
	struct in6_addr *addr, *mask;
	int sockfd;
	int bits;
	u_char *cp;

	printf(">>> ip6_config(\"%s\", \"%s\")\n", iface, cidr);

	memset(&ifra, 0, sizeof ifra);

	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_len = sizeof (struct sockaddr_in6);

	addr = &(ifra.ifra_addr.sin6_addr);
	mask = &(ifra.ifra_prefixmask.sin6_addr);

	strncpy(ifra.ifra_name, iface, sizeof ifra.ifra_name);

	if (inet_cidr_pton(AF_INET6, cidr, addr, &bits)) {
		printf("FAILED: inet_cidr_pton(): %s\n", strerror(errno));
		return;
	}

	bits = (bits <= 0)?128:bits;
	for (cp = (u_char *)mask; bits > 7; bits -= 8) *cp++ = 0xff;
	*cp = 0xff << (8 - bits);

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		printf("FAILED: socket(): %s\n", strerror(errno));
		return;
	}

	if (ioctl(sockfd, SIOCAIFADDR_IN6, &ifra))
		printf("FAILED: ioctl(): %s\n", strerror(errno));

	close(sockfd);
}

static void
ip4_config(const char* iface, const char* cidr)
{
	struct in_aliasreq ifra;
	struct in_addr *addr, *mask;
	int sockfd;
	int bits;

	printf(">>> ip4_config(\"%s\", \"%s\")\n", iface, cidr);

	memset(&ifra, 0, sizeof ifra);

	ifra.ifra_addr.sin_family = AF_INET;
	ifra.ifra_mask.sin_family = AF_INET;
	ifra.ifra_addr.sin_len = sizeof (struct sockaddr_in);
	ifra.ifra_mask.sin_len = sizeof (struct sockaddr_in);

	addr = &(ifra.ifra_addr.sin_addr);
	mask = &(ifra.ifra_mask.sin_addr);

	strncpy(ifra.ifra_name, iface, sizeof ifra.ifra_name);

	if (inet_cidr_pton(AF_INET, cidr, addr, &bits)) {
		printf("FAILED: inet_cidr_pton(): %s\n", strerror(errno));
		return;
	}

	if (bits) mask->s_addr = htonl(0xffffffff << (32 -bits));

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("FAILED: socket(): %s\n", strerror(errno));
		return;
	}

	if (ioctl(sockfd, SIOCAIFADDR, &ifra))
		printf("FAILED: ioctl(): %s\n", strerror(errno));

	close(sockfd);
}

static void
ip6_route(const char* dst, const char* gw)
{
	struct sockaddr_storage so[3];
	struct sockaddr_in6 *sin;
	struct in6_addr *addr, *mask, *via;
	int bits;
	int i;
	int addr_not_null = 0;
	u_char *cp;

	printf(">>> ip6_route(\"%s\", \"%s\")\n", dst, gw);

	memset(so, 0, sizeof so);
	for (i = 0; i < 3; i++) {
		sin = (struct sockaddr_in6*)&so[i];
		sin->sin6_family = AF_INET6;
		sin->sin6_len = sizeof (struct sockaddr_in6);
	}
	addr = &(((struct sockaddr_in6*)&so[0])->sin6_addr);
	via = &(((struct sockaddr_in6*)&so[1])->sin6_addr);
	mask = &(((struct sockaddr_in6*)&so[2])->sin6_addr);

	if (inet_cidr_pton(AF_INET6, dst, addr, &bits)) {
		printf("FAILED: invalid dst\n");
		return;
	}

	for (i = 0; i < 16; i++) addr_not_null |= addr->s6_addr[i];
	if (addr_not_null) bits = (bits <= 0)?128:bits;
	else bits = (bits < 0)?0:bits;

	for (cp = (u_char*)mask; bits > 7; bits -= 8) *cp++ = 0xff;
	*cp = 0xff << (8 -bits);

	if (inet_cidr_pton(AF_INET6, gw, via, &bits) || bits != -1) {
		printf("FAILED: invalid gw\n");
		return;
	}

	route_add(so);
}

static void
ip4_route(const char* dst, const char* gw)
{
	struct sockaddr_storage so[3];
	struct sockaddr_in *sin;
	struct in_addr *addr, *mask, *via;
	int bits;
	int i;

	printf(">>> ip4_route(\"%s\", \"%s\")\n", dst, gw);

	memset(so, 0, sizeof so);
	for (i = 0; i < 3; i++) {
		sin = (struct sockaddr_in*)&so[i];
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof (struct sockaddr_in);
	}
	addr = &(((struct sockaddr_in*)&so[0])->sin_addr);
	via = &(((struct sockaddr_in*)&so[1])->sin_addr);
	mask = &(((struct sockaddr_in*)&so[2])->sin_addr);

	if (inet_cidr_pton(AF_INET, dst, addr, &bits)) {
		printf("FAILED: invalid dst\n");
		return;
	}

	if (addr->s_addr != 0) bits = (bits == 0)?32:bits;
	else bits = (bits == 32)?0:bits;

	if (bits) mask->s_addr = htonl(0xffffffff << (32 - bits));

	if (inet_cidr_pton(AF_INET, gw, via, &bits) || bits != 32) {
		printf("FAILED: invalid gw\n");
		return;
	}

	route_add(so);
}

static void
route_add(struct sockaddr_storage *so)
{
	struct {
		struct rt_msghdr m_rtm;
		char   m_space[512];
	} m_rtmsg;
	char *cp = m_rtmsg.m_space;
	int i, l;
	int sockfd;

	for (i = 0; i < 3; i++) {
		l = SA_SIZE(&(so[i]));
		memmove(cp, (char *)&so[i], l);
		cp += l;
	}

	m_rtmsg.m_rtm.rtm_type = RTM_ADD;
	m_rtmsg.m_rtm.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
	m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
	m_rtmsg.m_rtm.rtm_seq = 1;
	m_rtmsg.m_rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

	if ((sockfd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		printf("FAILED: socket(): %s\n", strerror(errno));
		return;
	}

	if (write(sockfd, (char *)&m_rtmsg, l) < 0)
		printf("FAILED: writing to routing socket: %d\n", errno);

	close(sockfd);
}

static void
setup_signal_handlers()
{
	struct sigaction sa;
	sigset_t mask_everything;

	sa.sa_handler = handle_signal;
	sigfillset(&mask_everything);
	sa.sa_mask = mask_everything;
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_flags = 0;
	sa.sa_mask = mask_everything;
	sigaction(SIGINT, &sa, NULL);
	sa.sa_flags = 0;
	sa.sa_mask = mask_everything;
	sigaction(SIGALRM, &sa, NULL);
}

static void
handle_signal(int sig)
{
	switch (sig) {
	case SIGTERM: Reboot = RB_POWEROFF; break;
	case SIGINT: Reboot = RB_AUTOBOOT; break;
	case SIGALRM: Alarm = 1; break;
	}
}

static void
loop_start_prog()
{
	char *argv[] = {NULL, NULL};
	char default_prog[] = START_PROG;
	char kenv_value[512];
	pid_t pid;
	int status, ret;


	for (;;) {
		if (kenv(KENV_GET, "minit.start_prog", kenv_value,
		    (sizeof kenv_value) -1) > 0)
			argv[0] = kenv_value;
		else
			argv[0] = default_prog;

		printf("> loop_start_prog()\n\n%s\n\n", argv[0]);
		if ((pid = fork()) == -1) {
			printf("FAILED: fork(): %s", strerror(errno));
			return;
		}
		if (pid == 0) execv(argv[0], argv);

		ret = waitpid(pid, &status, WEXITED | WSTOPPED);

		setup_console();
		kill_all();

		if (ret == -1 && Reboot != 0) {/* sigterm or sigint received */
			return;
		} else if (WEXITSTATUS(status) == SIGTERM) {
			Reboot = RB_POWEROFF;
			return;
		} else if (WEXITSTATUS(status) == SIGINT) {
			Reboot = RB_AUTOBOOT;
			return;
		}
	}
}

static void
kill_all()
{
	static const int death_sigs[2] = { SIGTERM, SIGKILL };
	int i;

	printf("> kill_all()\n");
	for (i = 0; i < 2; i++) {
		if (kill(-1, death_sigs[i]) == -1 && errno == ESRCH)
			break;
		Alarm = 0;
		alarm(KILL_GRACE_TIME);
		do waitpid(-1, (int*)0, 0);
		while (errno != ECHILD && Alarm == 0);
	}
	alarm(0);
}
