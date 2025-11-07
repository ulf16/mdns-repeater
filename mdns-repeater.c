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
};

struct subnet {
    struct in_addr addr;    /* subnet addr */
    struct in_addr mask;    /* subnet mask */
    struct in_addr net;     /* subnet net (computed) */
};

int server_sockfd = -1;

int num_socks = 0;
struct if_sock socks[MAX_SOCKS];

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
    if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return r;
    }
#ifdef SO_REUSEPORT
    setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* bind to INADDR_ANY: receive multicast */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(MDNS_PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
        log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
    }

    /* enable loopback */
    if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
        log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
        return r;
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
            "maximum number of interfaces is 5\n\n"
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

    while (! shutdown_flag) {
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        FD_ZERO(&sockfd_set);
        FD_SET(server_sockfd, &sockfd_set);
        int numfd = select(server_sockfd + 1, &sockfd_set, NULL, NULL, &tv);
        if (numfd <= 0) continue;

        if (FD_ISSET(server_sockfd, &sockfd_set)) {
            struct sockaddr_in fromaddr;
			memset(&fromaddr, 0, sizeof(fromaddr));
            socklen_t sockaddr_size = sizeof(struct sockaddr_in);

            ssize_t recvsize = recvfrom(server_sockfd, pkt_data, PACKET_SIZE, 0,
                                        (struct sockaddr *) &fromaddr, &sockaddr_size);
            if (recvsize < 0) {
                if (recvsize < 0) {
            		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                		continue; /* benign transient */
            		}
            		log_message(LOG_ERR, "recv(): %s", strerror(errno));
        		}
        	continue;
            }

            int j;
            char discard = 0;
            char our_net = 0;
            for (j = 0; j < num_socks; j++) {
                /* packet originated from one of our nets? */
                if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr) {
                    our_net = 1;
                }
                /* loopback check */
                if (fromaddr.sin_addr.s_addr == socks[j].addr.s_addr) {
                    discard = 1; break;
                }
            }
            if (discard || !our_net) continue;

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

            if (log_verbosity > 0)
                log_message(LOG_DEBUG, "data from=%s size=%zd", inet_ntoa(fromaddr.sin_addr), recvsize);

            for (j = 0; j < num_socks; j++) {
                /* do not repeat to the source network */
                if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
                    continue;

                if (log_verbosity > 0)
                    log_message(LOG_DEBUG, "repeating data to %s", socks[j].ifname);

                ssize_t sentsize = send_packet(socks[j].sockfd, pkt_data, (size_t) recvsize);
                if (sentsize != recvsize) {
                    if (sentsize < 0)
                        log_message(LOG_ERR, "send(): %s", strerror(errno));
                    else
                        log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd", recvsize, sentsize);
                }
            }
        }
    }

    log_message(LOG_INFO, "shutting down...");

end_main:

    if (pkt_data != NULL) free(pkt_data);
    if (server_sockfd >= 0) close(server_sockfd);
    for (int i = 0; i < num_socks; i++) close(socks[i].sockfd);

    if (already_running() == getpid()) unlink(pid_file);

    log_message(LOG_INFO, "exit.");
    return r;
}
