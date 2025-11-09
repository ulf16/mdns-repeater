/*
 * mdns-repeater.c - mDNS repeater daemon (systemd-friendly)
 * Original Copyright (C) 2011 Darell Tan
 * Modified 2025 for foreground-by-default/systemd use
 *
 * GPLv2 or later
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>

#define PACKAGE "mdns-repeater"
#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#ifndef PIDFILE
#define PIDFILE "/var/run/" PACKAGE ".pid"
#endif

#define MAX_SOCKS 16
#define MAX_SUBNETS 16

struct if_sock {
    const char *ifname; /* interface name  */
    int sockfd;         /* socket filedesc */
    struct in_addr addr;/* interface addr  */
    struct in_addr mask;/* interface mask  */
    struct in_addr net; /* interface network (computed) */
    int ifindex;                 /* kernel ifindex */
    struct sockaddr_in last_querier;  /* last querier we proxied for */
    time_t last_querier_ts;      /* timestamp of last querier */
    int last_querier_sock_index; /* which local iface should reply back */
    int sockfd6;                         /* IPv6 send socket */
    struct sockaddr_in6 last_querier6;   /* last IPv6 querier */
    time_t last_querier6_ts;             /* timestamp */
    int last_querier6_sock_index;        /* opposite iface index */
};

struct subnet {
    struct in_addr addr;    /* subnet addr */
    struct in_addr mask;    /* subnet mask */
    struct in_addr net;     /* subnet net (computed) */
};

int server_sockfd = -1;
int server_sockfd6 = -1;

int num_socks = 0;
struct if_sock socks[MAX_SOCKS];

#define QUERIER_TTL 5 /* seconds */

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

int num_blacklisted_subnets = 0;
struct subnet blacklisted_subnets[MAX_SUBNETS];

int num_whitelisted_subnets = 0;
struct subnet whitelisted_subnets[MAX_SUBNETS];

#define PACKET_SIZE 65536
void *pkt_data = NULL;

/* Behaviour flags */
static int run_foreground = 1;      /* default: foreground */
static int daemonize_flag = 0;      /* set by -d */
static int shutdown_flag = 0;
static int log_to_stderr = 0;       /* default: syslog */
static int log_verbosity = 0;       /* -1=quiet, 0=normal, 1=verbose */

char *pid_file = PIDFILE;
const struct passwd* user = NULL;

static void log_message(int prio, const char *fmt, ...) {
    if (log_verbosity < 0 && prio > LOG_ERR) return; /* quiet: errors only */
    va_list ap;
    va_start(ap, fmt);
    if (log_to_stderr) {
        FILE *out = (prio <= LOG_ERR) ? stderr : stdout;
        vfprintf(out, fmt, ap);
        fputc('\n', out);
        fflush(out);
    } else {
        vsyslog(prio, fmt, ap);
    }
    va_end(ap);
}

static int create_recv_sock() {
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
        return sd;
    }

    int r = -1;
    int on = 1;
#ifdef SO_REUSEPORT
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* allow port sharing with Avahi/mDNSResponder before bind */
    if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return r;
    }

    /* bind to INADDR_ANY: receive multicast */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(MDNS_PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
        log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
    }

#ifdef IP_PKTINFO
    if ((r = setsockopt(sd, SOL_IP, IP_PKTINFO, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
        return r;
    }
#endif

    return sd;
}

static int create_send_sock(int recv_sockfd, const char *ifname, struct if_sock *sockdata) {
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        log_message(LOG_ERR, "send socket(): %s", strerror(errno));
        return sd;
    }

    sockdata->ifname = ifname;
    sockdata->sockfd = sd;

    int r = -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	/* get ifindex */
	if (ioctl(sd, SIOCGIFINDEX, &ifr) == 0) {
    	sockdata->ifindex = ifr.ifr_ifindex;
	} else {
    	sockdata->ifindex = -1;
	}

	/* reset per-iface querier cache */
	memset(&sockdata->last_querier, 0, sizeof(sockdata->last_querier));
	sockdata->last_querier.sin_family = AF_UNSPEC;
	sockdata->last_querier_ts = 0;
	sockdata->last_querier_sock_index = -1;
    struct in_addr *if_addr = &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

#ifdef SO_BINDTODEVICE
    if ((r = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq))) < 0) {
        log_message(LOG_ERR, "send setsockopt(SO_BINDTODEVICE): %s", strerror(errno));
        return r;
    }
#endif

    /* get netmask */
    if (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0) {
        memcpy(&sockdata->mask, if_addr, sizeof(struct in_addr));
    }

    /* get interface address */
    if (ioctl(sd, SIOCGIFADDR, &ifr) == 0) {
        memcpy(&sockdata->addr, if_addr, sizeof(struct in_addr));
    }

    /* compute network (address & mask) */
    sockdata->net.s_addr = sockdata->addr.s_addr & sockdata->mask.s_addr;

    int on = 1;
    if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "send setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return r;
    }
#ifdef SO_REUSEPORT
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* bind to interface address */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(MDNS_PORT);
    serveraddr.sin_addr.s_addr = if_addr->s_addr;
    if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
        log_message(LOG_ERR, "send bind(): %s", strerror(errno));
    }

#if __FreeBSD__
    if((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &serveraddr.sin_addr, sizeof(serveraddr.sin_addr))) < 0) {
        log_message(LOG_ERR, "send ip_multicast_if(): errno %d: %s", errno, strerror(errno));
    }
#endif

    /* join multicast group on receiving socket for this interface */
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(struct ip_mreq));
    mreq.imr_interface.s_addr = if_addr->s_addr;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
    if ((r = setsockopt(recv_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) {
        log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
        return r;
    }

    /* enable loopback */
    if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
        return r;
    }

    int ttl = 255; /* RFC6762 §11 */
    if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) < 0) {
        log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_TTL): %s", strerror(errno));
        return r;
    }

    char *addr_str = strdup(inet_ntoa(sockdata->addr));
    char *mask_str = strdup(inet_ntoa(sockdata->mask));
    char *net_str  = strdup(inet_ntoa(sockdata->net));
    log_message(LOG_INFO, "dev %s addr %s mask %s net %s", ifr.ifr_name, addr_str, mask_str, net_str);
    free(addr_str); free(mask_str); free(net_str);

    return sd;
}

static ssize_t send_packet(int fd, const void *data, size_t len) {
    static struct sockaddr_in toaddr;
    if (toaddr.sin_family != AF_INET) {
        memset(&toaddr, 0, sizeof(struct sockaddr_in));
        toaddr.sin_family = AF_INET;
        toaddr.sin_port = htons(MDNS_PORT);
        toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
    }
    return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}

static ssize_t send_unicast_to(int fd, struct in_addr to, const void *data, size_t len) {
    struct sockaddr_in toaddr;
    memset(&toaddr, 0, sizeof(toaddr));
    toaddr.sin_family = AF_INET;
    toaddr.sin_port = htons(MDNS_PORT);
    toaddr.sin_addr = to;
    return sendto(fd, data, len, 0, (struct sockaddr *)&toaddr, sizeof(toaddr));
}

static ssize_t send_unicast_to_sockaddr(int fd, const struct sockaddr_in *to, const void *data, size_t len) {
    struct sockaddr_in dst = *to;
    if (dst.sin_port == 0) dst.sin_port = htons(MDNS_PORT);
    return sendto(fd, data, len, 0, (const struct sockaddr *)&dst, sizeof(dst));
}

static ssize_t send_packet6(int fd, int ifindex, const void *data, size_t len) {
    struct sockaddr_in6 to6;
    memset(&to6, 0, sizeof(to6));
    to6.sin6_family = AF_INET6;
    to6.sin6_port = htons(MDNS_PORT);
    inet_pton(AF_INET6, "ff02::fb", &to6.sin6_addr);
    to6.sin6_scope_id = ifindex; /* link-local scope for ff02:: */
    return sendto(fd, data, len, 0, (struct sockaddr *)&to6, sizeof(to6));
}

static ssize_t send_unicast6_to(int fd, const struct sockaddr_in6 *to, const void *data, size_t len) {
    struct sockaddr_in6 dst = *to;
    if (dst.sin6_port == 0) dst.sin6_port = htons(MDNS_PORT);
    return sendto(fd, data, len, 0, (struct sockaddr *)&dst, sizeof(dst));
}
static int create_recv_sock6() {
    int sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sd < 0) {
        log_message(LOG_ERR, "recv6 socket(): %s", strerror(errno));
        return sd;
    }
    int r = -1;
    int on = 1;
#ifdef SO_REUSEPORT
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv6 setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return r;
    }
    /* v6-only */
    if ((r = setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv6 setsockopt(IPV6_V6ONLY): %s", strerror(errno));
        return r;
    }
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(MDNS_PORT);
    addr6.sin6_addr = in6addr_any;
    if ((r = bind(sd, (struct sockaddr *)&addr6, sizeof(addr6))) < 0) {
        log_message(LOG_ERR, "recv6 bind(): %s", strerror(errno));
    }
    /* want pktinfo */
    if ((r = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv6 setsockopt(IPV6_RECVPKTINFO): %s", strerror(errno));
        return r;
    }
    return sd;
}

static int create_send_sock6(int recv_sockfd6, const char *ifname, struct if_sock *sockdata) {
    int sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sd < 0) {
        log_message(LOG_ERR, "send6 socket(): %s", strerror(errno));
        return sd;
    }
    sockdata->sockfd6 = sd;

    int r = -1;
    int on = 1;
    if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "send6 setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return r;
    }
#ifdef SO_REUSEPORT
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* For IPv6 we don't bind to a specific addr; use ANY and select IF on send */
    struct sockaddr_in6 any6;
    memset(&any6, 0, sizeof(any6));
    any6.sin6_family = AF_INET6;
    any6.sin6_port = htons(0);
    any6.sin6_addr = in6addr_any;
    if ((r = bind(sd, (struct sockaddr *)&any6, sizeof(any6))) < 0) {
        log_message(LOG_ERR, "send6 bind(): %s", strerror(errno));
    }

    /* Join ff02::fb on this interface via the recv socket */
    if (sockdata->ifindex > 0) {
        struct ipv6_mreq mreq6;
        memset(&mreq6, 0, sizeof(mreq6));
        inet_pton(AF_INET6, "ff02::fb", &mreq6.ipv6mr_multiaddr);
        mreq6.ipv6mr_interface = sockdata->ifindex;
        if ((r = setsockopt(recv_sockfd6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6))) < 0) {
            log_message(LOG_ERR, "recv6 setsockopt(IPV6_JOIN_GROUP %s): %s", ifname, strerror(errno));
            return r;
        }
    }

    /* Multicast hops/loop default */
    int hops = 255;
    setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
    setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on));

    /* reset IPv6 querier cache */
    memset(&sockdata->last_querier6, 0, sizeof(sockdata->last_querier6));
    sockdata->last_querier6.sin6_family = AF_UNSPEC;
    sockdata->last_querier6_ts = 0;
    sockdata->last_querier6_sock_index = -1;

    return sd;
}

static void mdns_repeater_shutdown(int sig) {
    (void)sig;
    shutdown_flag = 1;
}

static pid_t already_running() {
    FILE *f;
    int count;
    pid_t pid;

    f = fopen(pid_file, "r");
    if (f != NULL) {
        count = fscanf(f, "%d", &pid);
        fclose(f);
        if (count == 1) {
            if (kill(pid, 0) == 0)
                return pid;
        }
    }
    return -1;
}

static int write_pidfile() {
    FILE *f;
    int r;

    f = fopen(pid_file, "w");
    if (f != NULL) {
        r = fprintf(f, "%d", getpid());
        fclose(f);
        return (r > 0);
    }
    return 0;
}

static void daemonize_now() {
    pid_t running_pid;
    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERR, "fork(): %s", strerror(errno));
        exit(1);
    }
    if (pid > 0)
        exit(0); /* parent exits */

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, mdns_repeater_shutdown);

    setsid();
    umask(0027);
    if (chdir("/") < 0) {
        log_message(LOG_ERR, "unable to change to root directory");
        exit(1);
    }

    for (int i = 0; i < 3; i++) {
        close(i);
        if (open("/dev/null", O_RDWR) != i) {
            log_message(LOG_ERR, "unable to open /dev/null for fd %d", i);
            exit(1);
        }
    }

    running_pid = already_running();
    if (running_pid != -1) {
        log_message(LOG_ERR, "already running as pid %d", running_pid);
        exit(1);
    } else if (! write_pidfile()) {
        log_message(LOG_ERR, "unable to write pid file %s", pid_file);
        exit(1);
    }
}

static void switch_user() {
    errno = 0;
    if (setgid(user->pw_gid) != 0) {
        log_message(LOG_ERR, "Failed to switch to group %d - %s", user->pw_gid, strerror(errno));
        exit(2);
    } else if (setuid(user->pw_uid) != 0) {
        log_message(LOG_ERR, "Failed to switch to user %s (%d) - %s", user->pw_name, user->pw_uid, strerror(errno));
        exit(2);
    }
}

static void show_help(const char *progname) {
    fprintf(stderr, "mDNS repeater (version " HGVERSION ")\n");
    fprintf(stderr, "Copyright (C) 2011 Darell Tan\n\n");

    fprintf(stderr, "usage: %s [options] <ifdev> ...\n", progname);
    fprintf(stderr,
            "\n<ifdev> specifies an interface like \"eth0\"\n"
            "packets received on an interface are repeated across all other specified interfaces\n"
            "maximum number of interfaces is 16\n\n"
            "Options:\n"
            "  -d, --daemonize       Run in background (default: foreground)\n"
            "  -f, --foreground      Run in foreground (default)\n"
            "  -q, --quiet           Errors only\n"
            "  -v, --verbose         Verbose packet logging\n"
            "  -S, --stderr          Log to stderr instead of syslog\n"
            "  -b <subnet>           Blacklist subnet (e.g. 192.168.1.0/24)\n"
            "  -w <subnet>           Whitelist subnet (mutually exclusive with -b)\n"
            "  -p <path>             PID file path (absolute)\n"
            "  -u <user>             Run as user\n"
            "  -h, --help            Show this help\n");
}

static int parse(char *input, struct subnet *s) {
    int delim = 0;
    int end = 0;
    while (input[end] != 0) {
        if (input[end] == '/') {
            delim = end;
        }
        end++;
    }
    if (end == 0 || delim == 0 || end == delim) {
        return -1;
    }

    char *addr = (char*) malloc(end);
    memset(addr, 0, end);
    strncpy(addr, input, delim);
    if (inet_pton(AF_INET, addr, &s->addr) != 1) {
        free(addr);
        return -2;
    }

    memset(addr, 0, end);
    strncpy(addr, input+delim+1, end-delim-1);
    int mask = atoi(addr);
    free(addr);

    if (mask < 0 || mask > 32) {
        return -3;
    }

    s->mask.s_addr = ntohl((uint32_t)0xFFFFFFFF << (32 - mask));
    s->net.s_addr = s->addr.s_addr & s->mask.s_addr;

    return 0;
}

static int tostring(struct subnet *s, char* buf, int len) {
    char *addr_str = strdup(inet_ntoa(s->addr));
    char *mask_str = strdup(inet_ntoa(s->mask));
    char *net_str = strdup(inet_ntoa(s->net));
    int l = snprintf(buf, len, "addr %s mask %s net %s", addr_str, mask_str, net_str);
    free(addr_str); free(mask_str); free(net_str);
    return l;
}

static int parse_opts(int argc, char *argv[]) {
    int c, res;
    int help = 0;
    struct subnet *ss;
    char *msg;
    while ((c = getopt(argc, argv, "hdfqvSp:b:w:u:")) != -1) {
        switch (c) {
            case 'h': help = 1; break;
            case 'd': daemonize_flag = 1; run_foreground = 0; break;
            case 'f': daemonize_flag = 0; run_foreground = 1; break;
            case 'q': log_verbosity = -1; break;
            case 'v': log_verbosity = 1; break;
            case 'S': log_to_stderr = 1; break;
            case 'p':
                if (optarg[0] != '/')
                    log_message(LOG_ERR, "pid file path must be absolute");
                else
                    pid_file = optarg;
                break;
            case 'b':
                if (num_blacklisted_subnets >= MAX_SUBNETS) {
                    log_message(LOG_ERR, "too many blacklisted subnets (maximum is %d)", MAX_SUBNETS);
                    exit(2);
                }
                if (num_whitelisted_subnets != 0) {
                    log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
                    exit(2);
                }
                ss = &blacklisted_subnets[num_blacklisted_subnets];
                res = parse(optarg, ss);
                switch (res) {
                    case -1: log_message(LOG_ERR, "invalid blacklist argument"); exit(2);
                    case -2: log_message(LOG_ERR, "could not parse netmask"); exit(2);
                    case -3: log_message(LOG_ERR, "invalid netmask"); exit(2);
                }
                num_blacklisted_subnets++;
                msg = malloc(128); memset(msg, 0, 128); tostring(ss, msg, 128);
                log_message(LOG_INFO, "blacklist %s", msg); free(msg);
                break;
            case 'w':
                if (num_whitelisted_subnets >= MAX_SUBNETS) {
                    log_message(LOG_ERR, "too many whitelisted subnets (maximum is %d)", MAX_SUBNETS);
                    exit(2);
                }
                if (num_blacklisted_subnets != 0) {
                    log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
                    exit(2);
                }
                ss = &whitelisted_subnets[num_whitelisted_subnets];
                res = parse(optarg, ss);
                switch (res) {
                    case -1: log_message(LOG_ERR, "invalid whitelist argument"); exit(2);
                    case -2: log_message(LOG_ERR, "could not parse netmask"); exit(2);
                    case -3: log_message(LOG_ERR, "invalid netmask"); exit(2);
                }
                num_whitelisted_subnets++;
                msg = malloc(128); memset(msg, 0, 128); tostring(ss, msg, 128);
                log_message(LOG_INFO, "whitelist %s", msg); free(msg);
                break;
            case 'u':
                if ((user = getpwnam(optarg)) == NULL) {
                    log_message(LOG_ERR, "No such user '%s'", optarg);
                    exit(2);
                }
                break;
            default:
                log_message(LOG_ERR, "unknown option %c", optopt);
                exit(2);
        }
    }

    if (help) {
        show_help(argv[0]);
        exit(0);
    }

    return optind;
}

int main(int argc, char *argv[]) {
    pid_t running_pid;
    fd_set sockfd_set;
    int r = 0;

    parse_opts(argc, argv);

    if ((argc - optind) <= 1) {
        show_help(argv[0]);
        log_message(LOG_ERR, "error: at least 2 interfaces must be specified");
        exit(2);
    }

    openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_DAEMON);

    /* create receiving socket */
    server_sockfd = create_recv_sock();
    if (server_sockfd < 0) {
        log_message(LOG_ERR, "unable to create server socket");
        r = 1;
        goto end_main;
    }
    server_sockfd6 = create_recv_sock6();
    if (server_sockfd6 < 0) {
        log_message(LOG_ERR, "unable to create IPv6 server socket (continuing without IPv6)");
    }

    /* create sending sockets */
    int i;
    for (i = optind; i < argc; i++) {
        if (num_socks >= MAX_SOCKS) {
            log_message(LOG_ERR, "too many sockets (maximum is %d)", MAX_SOCKS);
            exit(2);
        }
        int sockfd = create_send_sock(server_sockfd, argv[i], &socks[num_socks]);
        if (sockfd < 0) {
            log_message(LOG_ERR, "unable to create socket for interface %s", argv[i]);
            r = 1;
            goto end_main;
        }
        if (server_sockfd6 >= 0) {
            int sockfd6 = create_send_sock6(server_sockfd6, argv[i], &socks[num_socks]);
            if (sockfd6 < 0) {
                log_message(LOG_ERR, "unable to create IPv6 socket for interface %s", argv[i]);
            }
        } else {
            socks[num_socks].sockfd6 = -1;
        }
        num_socks++;
    }

    if (user) {
        switch_user();
    }

    if (daemonize_flag) {
        daemonize_now();
    } else {
        /* Foreground: ensure we are not double-running */
        running_pid = already_running();
        if (running_pid != -1) {
            log_message(LOG_ERR, "already running as pid %d", running_pid);
            exit(1);
        }
    }

    pkt_data = malloc(PACKET_SIZE);
    if (pkt_data == NULL) {
        log_message(LOG_ERR, "cannot malloc() packet buffer: %s", strerror(errno));
        r = 1;
        goto end_main;
    }

	struct sockaddr_in mdns_mcast;
	memset(&mdns_mcast, 0, sizeof(mdns_mcast));
	mdns_mcast.sin_family = AF_INET;
	mdns_mcast.sin_port = htons(MDNS_PORT);
	mdns_mcast.sin_addr.s_addr = inet_addr(MDNS_ADDR);

	char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];

    while (! shutdown_flag) {
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        FD_ZERO(&sockfd_set);
        int maxfd = -1;
        if (server_sockfd >= 0) { FD_SET(server_sockfd, &sockfd_set); if (server_sockfd > maxfd) maxfd = server_sockfd; }
        if (server_sockfd6 >= 0) { FD_SET(server_sockfd6, &sockfd_set); if (server_sockfd6 > maxfd) maxfd = server_sockfd6; }
        int numfd = select(maxfd + 1, &sockfd_set, NULL, NULL, &tv);
        if (numfd <= 0) continue;

        if (FD_ISSET(server_sockfd, &sockfd_set)) {
           struct sockaddr_in fromaddr;
memset(&fromaddr, 0, sizeof(fromaddr));

struct msghdr msg;
struct iovec iov;
struct cmsghdr *cmsg;
struct in_pktinfo *pi = NULL;
struct sockaddr_in dstaddr;
memset(&dstaddr, 0, sizeof(dstaddr));

iov.iov_base = pkt_data;
iov.iov_len  = PACKET_SIZE;

memset(&msg, 0, sizeof(msg));
msg.msg_name = &fromaddr;
msg.msg_namelen = sizeof(fromaddr);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;
msg.msg_control = cmsgbuf;
msg.msg_controllen = sizeof(cmsgbuf);

ssize_t recvsize = recvmsg(server_sockfd, &msg, 0);
if (recvsize <= 0) {
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
        }
        if (server_sockfd6 >= 0 && FD_ISSET(server_sockfd6, &sockfd_set)) {
            struct sockaddr_in6 from6; memset(&from6, 0, sizeof(from6));
            struct msghdr msg6; struct iovec iov6; struct cmsghdr *cmsg6; struct in6_pktinfo *pi6 = NULL;
            iov6.iov_base = pkt_data; iov6.iov_len = PACKET_SIZE;
            char cmsgbuf6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
            memset(&msg6, 0, sizeof(msg6));
            msg6.msg_name = &from6; msg6.msg_namelen = sizeof(from6);
            msg6.msg_iov = &iov6; msg6.msg_iovlen = 1;
            msg6.msg_control = cmsgbuf6; msg6.msg_controllen = sizeof(cmsgbuf6);
            ssize_t n6 = recvmsg(server_sockfd6, &msg6, 0);
            if (n6 <= 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) goto after_ipv6;
                log_message(LOG_ERR, "recvmsg6(): %s", strerror(errno));
                goto after_ipv6;
            }
            for (cmsg6 = CMSG_FIRSTHDR(&msg6); cmsg6; cmsg6 = CMSG_NXTHDR(&msg6, cmsg6)) {
                if (cmsg6->cmsg_level == IPPROTO_IPV6 && cmsg6->cmsg_type == IPV6_PKTINFO) {
                    pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg6);
                    break;
                }
            }
            if (!pi6) goto after_ipv6;
            int recv_if = pi6->ipi6_ifindex;
            /* Determine multicast vs unicast by dst */
            int is_mcast = IN6_IS_ADDR_MULTICAST(&pi6->ipi6_addr);
            int j;
            if (log_verbosity > 0) {
                char srcbuf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &from6.sin6_addr, srcbuf, sizeof(srcbuf));
                log_message(LOG_DEBUG, "v6 data from=%s size=%zd ifindex=%d mcast=%d", srcbuf, n6, recv_if, is_mcast);
            }
            /* find receiving socket index */
            int recv_sock_index = -1;
            for (j = 0; j < num_socks; j++) if (socks[j].ifindex == recv_if) { recv_sock_index = j; break; }

            /* Peek DNS header */
            int is_query = 0, is_response = 0;
            if (n6 >= (ssize_t)sizeof(struct dns_header)) {
                struct dns_header *dh = (struct dns_header*)pkt_data;
                uint16_t flags = ntohs(dh->flags);
                if ((flags & 0x8000) == 0) is_query = 1; else is_response = 1;
            }

            if (is_mcast) {
                for (j = 0; j < num_socks; j++) {
                    if (j == recv_sock_index) continue; /* don't echo back on same net */
                    if (socks[j].sockfd6 <= 0) continue;
                    if (log_verbosity > 0) log_message(LOG_DEBUG, "repeating v6 mcast to %s", socks[j].ifname);
                    ssize_t s = send_packet6(socks[j].sockfd6, socks[j].ifindex, pkt_data, (size_t)n6);
                    if (s != n6) {
                        if (s < 0) log_message(LOG_ERR, "send6: %s", strerror(errno));
                        else log_message(LOG_ERR, "send_packet6 size differs: sent=%zd actual=%zd", n6, s);
                    }
                    if (is_query) {
    					/* Preserve IPv6 querier sockaddr, including port */
    					socks[j].last_querier6 = from6;
    					socks[j].last_querier6_ts = time(NULL);
    					socks[j].last_querier6_sock_index = recv_sock_index;
					}
                }
                goto after_ipv6;
            }
            /* Unicast v6: forward to last querier if fresh */
            if (is_response && recv_sock_index >= 0) {
                time_t now = time(NULL);
                struct if_sock *in_if = &socks[recv_sock_index];
                if (in_if->last_querier6.sin6_family == AF_INET6 && in_if->last_querier6_ts && (now - in_if->last_querier6_ts) <= QUERIER_TTL) {
                    int out_idx = in_if->last_querier6_sock_index;
                    if (out_idx >= 0 && out_idx < num_socks && socks[out_idx].sockfd6 > 0) {
                        /* ensure scope for link-local */
                        struct sockaddr_in6 dst = in_if->last_querier6;
                        if (IN6_IS_ADDR_LINKLOCAL(&dst.sin6_addr)) dst.sin6_scope_id = socks[out_idx].ifindex;
                        ssize_t s = send_unicast6_to(socks[out_idx].sockfd6, &dst, pkt_data, (size_t)n6);
                        if (s != n6) {
                            if (s < 0) log_message(LOG_ERR, "send_unicast6: %s", strerror(errno));
                            else log_message(LOG_ERR, "send_unicast6 size differs: sent=%zd actual=%zd", n6, s);
                        }
                        goto after_ipv6;
                    }
                }
            }
            /* Fallback: mirror as multicast */
            for (j = 0; j < num_socks; j++) {
                if (j == recv_sock_index) continue;
                if (socks[j].sockfd6 <= 0) continue;
                ssize_t s = send_packet6(socks[j].sockfd6, socks[j].ifindex, pkt_data, (size_t)n6);
                if (s != n6) {
                    if (s < 0) log_message(LOG_ERR, "send6: %s", strerror(errno));
                    else log_message(LOG_ERR, "send_packet6 size differs: sent=%zd actual=%zd", n6, s);
                }
            }
        after_ipv6: ;
        }
    log_message(LOG_ERR, "recvmsg(): %s", strerror(errno));
    continue;
}

/* Extract IP_PKTINFO */
for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        pi = (struct in_pktinfo *) CMSG_DATA(cmsg);
        break;
    }
}
if (!pi) {
    if (log_verbosity > 0) log_message(LOG_DEBUG, "no IP_PKTINFO; skipping");
    continue;
}

memcpy(&dstaddr, &pi->ipi_addr, sizeof(struct in_addr));
dstaddr.sin_family = AF_INET;
dstaddr.sin_port = htons(MDNS_PORT);

int recv_if = pi->ipi_ifindex;

/* quick filters: accept anything that arrived on a configured iface; drop only self-looped */
int j;
char discard = 0;
for (j = 0; j < num_socks; j++) {
    if (fromaddr.sin_addr.s_addr == socks[j].addr.s_addr) { discard = 1; break; }
}
/* Ensure pktinfo has a valid ifindex */
if (discard || recv_if <= 0) continue;

/* whitelist/blacklist */
if (num_whitelisted_subnets != 0) {
    char whitelisted_packet = 0;
    for (j = 0; j < num_whitelisted_subnets; j++) {
        if ((fromaddr.sin_addr.s_addr & whitelisted_subnets[j].mask.s_addr) == whitelisted_subnets[j].net.s_addr) {
            whitelisted_packet = 1; break;
        }
    }
    if (!whitelisted_packet) {
        if (log_verbosity > 0)
            log_message(LOG_DEBUG, "skipping packet from=%s size=%zd", inet_ntoa(fromaddr.sin_addr), recvsize);
        continue;
    }
} else {
    char blacklisted_packet = 0;
    for (j = 0; j < num_blacklisted_subnets; j++) {
        if ((fromaddr.sin_addr.s_addr & blacklisted_subnets[j].mask.s_addr) == blacklisted_subnets[j].net.s_addr) {
            blacklisted_packet = 1; break;
        }
    }
    if (blacklisted_packet) {
        if (log_verbosity > 0)
            log_message(LOG_DEBUG, "skipping packet from=%s size=%zd", inet_ntoa(fromaddr.sin_addr), recvsize);
        continue;
    }
}

if (log_verbosity > 0) {
    char *src = strdup(inet_ntoa(fromaddr.sin_addr));
    char *dst = strdup(inet_ntoa(*(struct in_addr*)&dstaddr.sin_addr));
    log_message(LOG_DEBUG, "data from=%s to=%s size=%zd ifindex=%d", src, dst, recvsize, recv_if);
    free(src); free(dst);
}

int is_mcast = IN_MULTICAST(ntohl(dstaddr.sin_addr.s_addr));

/* Peek DNS header (12 bytes) */
int is_query = 0, is_response = 0;
if (recvsize >= (ssize_t)sizeof(struct dns_header)) {
    struct dns_header *dh = (struct dns_header*)pkt_data;
    uint16_t flags = ntohs(dh->flags);
    if ((flags & 0x8000) == 0) is_query = 1; else is_response = 1;
}

/* find which configured iface this arrived on */
int recv_sock_index = -1;
for (j = 0; j < num_socks; j++) {
    if (socks[j].ifindex == recv_if) { recv_sock_index = j; break; }
}

/* Multicast: mirror as multicast and remember querier */
if (is_mcast) {
    for (j = 0; j < num_socks; j++) {
        if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
            continue;

        if (log_verbosity > 0) log_message(LOG_DEBUG, "repeating mcast to %s", socks[j].ifname);

        ssize_t sentsize = send_packet(socks[j].sockfd, pkt_data, (size_t) recvsize);
        if (sentsize != recvsize) {
            if (sentsize < 0) log_message(LOG_ERR, "send(): %s", strerror(errno));
            else log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd", recvsize, sentsize);
        }

        if (is_query) {
    		/* Preserve the querier's full sockaddr (addr+port) */
    		socks[j].last_querier = fromaddr;
    		socks[j].last_querier_ts         = time(NULL);
    		socks[j].last_querier_sock_index = (recv_sock_index >= 0) ? recv_sock_index : -1;
		}
    }
    continue;
}

/* Unicast likely reply: forward as unicast to original querier */
if (is_response && recv_sock_index >= 0) {
    time_t now = time(NULL);
    struct if_sock *in_if = &socks[recv_sock_index];
    if (in_if->last_querier.sin_family == AF_INET &&
        in_if->last_querier_ts &&
        (now - in_if->last_querier_ts) <= QUERIER_TTL) {

        int out_idx = in_if->last_querier_sock_index;
        if (out_idx >= 0 && out_idx < num_socks) {
            if (log_verbosity > 0) {
                char *q = strdup(inet_ntoa(in_if->last_querier.sin_addr));
                log_message(LOG_DEBUG, "forwarding unicast resp from if %s -> querier %s via %s",
                            in_if->ifname, q, socks[out_idx].ifname);
                free(q);
            }
            ssize_t sentsize = send_unicast_to_sockaddr(socks[out_idx].sockfd, &in_if->last_querier,
                                            pkt_data, (size_t)recvsize);
            if (sentsize != recvsize) {
                if (sentsize < 0) log_message(LOG_ERR, "send_unicast_to(): %s", strerror(errno));
                else log_message(LOG_ERR, "send_unicast_to size differs: sent=%zd actual=%zd", recvsize, sentsize);
            }
            continue;
        }
    }
}

/* Fallback: mirror as multicast */
for (j = 0; j < num_socks; j++) {
    if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
        continue;
    if (log_verbosity > 0) log_message(LOG_DEBUG, "fallback repeating as mcast to %s", socks[j].ifname);
    ssize_t sentsize = send_packet(socks[j].sockfd, pkt_data, (size_t) recvsize);
    if (sentsize != recvsize) {
        if (sentsize < 0) log_message(LOG_ERR, "send(): %s", strerror(errno));
        else log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd", recvsize, sentsize);
    }
}
        }
    }

    log_message(LOG_INFO, "shutting down...");

end_main:

    if (pkt_data != NULL) free(pkt_data);
    if (server_sockfd >= 0) close(server_sockfd);
    if (server_sockfd6 >= 0) close(server_sockfd6);
    for (int i = 0; i < num_socks; i++) { if (socks[i].sockfd >= 0) close(socks[i].sockfd); if (socks[i].sockfd6 > 0) close(socks[i].sockfd6); }

    if (already_running() == getpid()) unlink(pid_file);

    log_message(LOG_INFO, "exit.");
    return r;
}
