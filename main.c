/* TCPMPing: TCP SYN ping multiple hosts                                       */
/* Author: goodlq11 <goodlq11@gmail.com>                                       */
/* Forked from http://www.programming-pcap.aldabaknocking.com/code/tcpsyndos.c */
/* Requires CAP_NET_RAW to work                                                */
/*                                                                             */
/* This code is distributed under the GPL License. For more info check:        */
/* http://www.gnu.org/copyleft/gpl.html                                        */

#define __USE_BSD /* Using BSD IP header           */
#include <netinet/in.h>
#include <netinet/ip.h> /* Internet Protocol             */
#include <sys/types.h>
#define __FAVOR_BSD      /* Using BSD TCP header          */
#include <netinet/tcp.h> /* Transmission Control Protocol */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <argp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* =========================================================================================== */
/* ==================================== TCP/IP Section ======================================= */
/* =========================================================================================== */

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
    uint32_t src;
    uint32_t dst;
    u_char zero;
    u_char protocol;
    uint16_t tcplen;
} tcp_phdr_t;

typedef uint16_t u_int16;
typedef uint32_t u_int32;

/* This piece of code has been used many times in a lot of differents tools. */
/* I haven't been able to determine the author of the code but it looks like */
/* this is a public domain implementation of the checksum algorithm */

unsigned short in_cksum(unsigned short* addr, int len) {
    u_short answer = 0;
    register u_short* w = addr;
    register int sum = 0;
    register int nleft = len;

    /*
   * Our algorithm is simple, using a 32-bit accumulator (sum),
   * we add sequential 16-bit words to it, and at the end, fold back 
   * all the carry bits from the top 16 bits into the lower 16 bits. 
   */

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char*)(&answer) = *(u_char*)w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* truncate to 16 bits */
    return answer;
}

void fill_sync_packet(char* packet, struct sockaddr_in* source_sockaddr_in, struct sockaddr_in* remote_sockaddr_in) {
    struct ip* ipheader = (struct ip*)packet;
    struct tcphdr* tcpheader = (struct tcphdr*)(packet + sizeof(struct ip));

    tcp_phdr_t pseudohdr;             /* TPC Pseudoheader (used in checksum)                                */
    static const int tcpsyn_len = 20; /* TCP Pseudoheader + TCP actual data used for computing the checksum */
    char tcpcsumblock[sizeof(tcp_phdr_t) + tcpsyn_len];

    memset(&pseudohdr, 0, sizeof(tcp_phdr_t));
    memset(&packet, 0, sizeof(packet));

    /* IP Header */
    ipheader->ip_hl = 5;  /* Header lenght in octects                       */
    ipheader->ip_v = 4;   /* Ip protocol version (IPv4)                     */
    ipheader->ip_tos = 0; /* Type of Service (Usually zero)                 */
    ipheader->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ipheader->ip_off = 0;  /* Fragment offset. We'll not use this            */
    ipheader->ip_ttl = 64; /* Time to live: 64 in Linux, 128 in Windows...   */
    ipheader->ip_p = 6;    /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
    ipheader->ip_sum = 0;  /* Checksum. It has to be zero for the moment     */
    ipheader->ip_id = htons(1337);
    ipheader->ip_src.s_addr = source_sockaddr_in->sin_addr.s_addr; /* Source IP address      */
    ipheader->ip_dst.s_addr = remote_sockaddr_in->sin_addr.s_addr; /* Destination IP address */

    /* TCP Header */
    tcpheader->th_seq = htonl(rand() % UINT32_MAX);     /* sequence number                         */
    tcpheader->th_ack = htonl(rand() % UINT32_MAX);     /* acknowledge number                      */
    tcpheader->th_x2 = 0;                               /* Variable in 4 byte blocks. (Deprecated) */
    tcpheader->th_off = 5;                              /* Segment offset (Lenght of the header)   */
    tcpheader->th_flags = TH_SYN;                       /* tcp flags reset and acknowledge         */
    tcpheader->th_win = htons(4500) + rand() % 1000;    /* Window size                             */
    tcpheader->th_urp = 0;                              /* Urgent pointer.                         */
    tcpheader->th_sport = source_sockaddr_in->sin_port; /* Source Port                             */
    tcpheader->th_dport = remote_sockaddr_in->sin_port; /* Destination Port                        */
    tcpheader->th_sum = 0;                              /* Checksum. (Zero until computed)         */

    /* Fill the pseudoheader so we can compute the TCP checksum*/
    pseudohdr.src = ipheader->ip_src.s_addr;
    pseudohdr.dst = ipheader->ip_dst.s_addr;
    pseudohdr.zero = 0;
    pseudohdr.protocol = ipheader->ip_p;
    pseudohdr.tcplen = htons(sizeof(struct tcphdr));

    /* Copy header and pseudoheader to a buffer to compute the checksum */
    memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));
    memcpy(tcpcsumblock + sizeof(tcp_phdr_t), tcpheader, sizeof(struct tcphdr));

    /* Compute the TCP checksum as the standard says (RFC 793) */
    tcpheader->th_sum = in_cksum((unsigned short*)(tcpcsumblock), sizeof(tcpcsumblock));

    /* Compute the IP checksum as the standard says (RFC 791) */
    ipheader->ip_sum = in_cksum((unsigned short*)ipheader, sizeof(struct ip));
}

/* =========================================================================================== */
/* ============================= NameResolution Section ====================================== */
/* =========================================================================================== */

struct sockaddr_in* find_sockaddr(const char* domain_name, const char* port, struct sockaddr_in* dest, const int ai_family) {
    struct addrinfo* res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = ai_family;

    const int error = getaddrinfo(domain_name, port, &hints, &res);
    if (error != 0) {
        fprintf(stderr, "%s: %s\n", domain_name, gai_strerror(error));
        return NULL;
    }
    memcpy(dest, (struct sockaddr_in*)res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);

    return dest;
}

/* =========================================================================================== */
/* ================================ Arguments Parser Section ================================= */
/* =========================================================================================== */

struct remote {
    char* host;
    char* port;
};
struct arguments {
    bool verbose;
    bool loose;
    char* source;
    char* port;
    int count;
    double timeout;
    double throttle;
    int remotes_count;
    struct remote* remotes;
};

const char* argp_program_version = "TCPMPing v0.0.1";
const char* argp_program_bug_address = "goodlq11 <goodlq11@gmail.com>";
static char doc[] = "\n"
                    "TCPMPing: TCP SYN ping multiple hosts\n"
                    "Author: goodlq11 <goodlq11@gmail.com>\n"
                    "Requires CAP_NET_RAW to work\n";
static char args_doc[] = "<remote_host>[:<remote_port>]...";
static struct argp_option options[] = {
    {"verbose", 'v', NULL, 0, "(default=false) verbose mode"},
    {"loose", 'l', NULL, 0, "(default=false) Accept non-TCP response packets"},
    {"source", 's', "<source_ip>", 0, "(default=0.0.0.0) Source IP address to use"},
    {"port", 'p', "<remote_port>", 0, "(default=80) Default remote port to use"},
    {"count", 'c', "<count>", 0, "(default=3) Stop after sending <count> packets"},
    {"timeout", 't', "<timeout>", 0, "(default=1.5) Time to wait for a response, in seconds"},
    {"throttle", 'r', "<throttle>", 0, "(default=0.3) Wait <throttle> seconds between sending each packet"},
    {0}};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;
    switch (key) {
        case 'v': {
            arguments->verbose = true;
            return 0;
        }
        case 'l': {
            arguments->loose = true;
            return 0;
        }
        case 's': {
            arguments->source = arg;
            return 0;
        }
        case 'p': {
            arguments->port = arg;
            return 0;
        }
        case 'c': {
            arguments->count = atoi(arg);
            return 0;
        }
        case 't': {
            arguments->timeout = atof(arg);
            return 0;
        }
        case 'r': {
            arguments->throttle = atof(arg);
            return 0;
        }
        case ARGP_KEY_ARG: {
            arguments->remotes_count++;
            arguments->remotes = realloc(arguments->remotes, arguments->remotes_count * sizeof(struct remote));
            arguments->remotes[arguments->remotes_count - 1].host = arg;
            char* port_string = strchr(arg, ':');
            if (port_string) {
                *port_string = '\0';
                arguments->remotes[arguments->remotes_count - 1].port = port_string + sizeof(char);
            }
            else {
                arguments->remotes[arguments->remotes_count - 1].port = NULL;
            }
            return 0;
        }
        case ARGP_KEY_END: {
            if (state->arg_num == 0) {
                argp_usage(state);
            }
            return 0;
        }
        default: {
            return ARGP_ERR_UNKNOWN;
        }
    }
    return 0;
}
static struct argp argp = {options, parse_opt, args_doc, doc};

/* =========================================================================================== */
/* ================================ Main ===================================================== */
/* =========================================================================================== */

int main(int argc, char* argv[]) {
    // 1. arguments parser
    struct arguments arguments;
    arguments.verbose = false;
    arguments.loose = false;
    arguments.source = NULL;
    arguments.port = "80";
    arguments.count = 3;
    arguments.timeout = 1.5;
    arguments.throttle = 0.3;
    arguments.remotes_count = 0;
    arguments.remotes = malloc(sizeof(struct remote) * 100);
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // 2. prepare API
    srand((int)time(NULL));
    const struct timespec throttle = {(int)arguments.throttle, (long)((arguments.throttle - (long)arguments.throttle) * 1000000000)};
    const struct timeval timeout = {(int)arguments.timeout, (long)((arguments.timeout - (long)arguments.timeout) * 1000000)};
    const bool verbose = arguments.verbose;
    const bool loose = arguments.loose;
    int i, j;

    // 3. resolve remotes
    struct sockaddr_in remotes_sockaddr_in[arguments.remotes_count];
    for (i = 0; i < arguments.remotes_count; i++) {
        if (!arguments.remotes[i].port) arguments.remotes[i].port = arguments.port;
        if (find_sockaddr(arguments.remotes[i].host, arguments.remotes[i].port, &remotes_sockaddr_in[i], AF_INET) == NULL) {
            memset(&remotes_sockaddr_in[i], 0, sizeof(remotes_sockaddr_in[i]));
            fprintf(stderr, "%s: will be skipped\n", arguments.remotes[i].host);
        }
    }

    // 4. resolve local
    struct sockaddr_in source_sockaddr_in_template;
    if (arguments.source) {
        if (find_sockaddr(arguments.source, NULL, &source_sockaddr_in_template, AF_INET) == NULL) {
            return -1;
        }
    }
    else {
        memset(&source_sockaddr_in_template, 0, sizeof(source_sockaddr_in_template));
        source_sockaddr_in_template.sin_family = AF_INET;
    }

    // 5. start ping and collect stats
    double stat[arguments.remotes_count][arguments.count];
    memset(&stat, 0, sizeof(stat));
    for (i = 0; i < arguments.count; i++) {
        for (j = 0; j < arguments.remotes_count; j++) {
            // 5.1 skip unresolved remote
            if (!remotes_sockaddr_in[j].sin_addr.s_addr) continue;

            // 5.2 prepare sockaddr_in
            struct sockaddr_in source_sockaddr_in_buffer = source_sockaddr_in_template;
            struct sockaddr_in* source_sockaddr_in = &source_sockaddr_in_buffer;
            struct sockaddr_in* remote_sockaddr_in = &remotes_sockaddr_in[j];

            // 5.3 create socket
            const int rawsocket = socket(remote_sockaddr_in->sin_family, SOCK_RAW, IPPROTO_TCP);
            if (rawsocket == -1) {
                fprintf(stderr, "%s: ", arguments.remotes[j].host);
                perror("socket");
                continue;
            }

            // 5.4 setup socket
            {
                // 5.4.1 set IP_HDRINCL
                static const int one = 1;
                if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
                    fprintf(stderr, "%s: ", arguments.remotes[j].host);
                    perror("setsockopt");
                    continue;
                }

                // 5.4.2 set SO_RCVTIMEO
                if (setsockopt(rawsocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                    fprintf(stderr, "%s: ", arguments.remotes[j].host);
                    perror("setsockopt");
                    continue;
                }
            }

            // 5.5 find the source ip we will use
            {
                // 5.5.1 bind hints, try to connect
                bind(rawsocket, (struct sockaddr*)source_sockaddr_in, sizeof(struct sockaddr_in));
                connect(rawsocket, (struct sockaddr*)remote_sockaddr_in, sizeof(struct sockaddr_in));

                // 5.5.2 get the infered ip
                u_short sin_port = source_sockaddr_in->sin_port;
                socklen_t source_sockaddr_in_len = sizeof(struct sockaddr_in);
                getsockname(rawsocket, (struct sockaddr*)source_sockaddr_in, &source_sockaddr_in_len);
                source_sockaddr_in->sin_port = sin_port;
            }

            // 5.6 find the source port we will use
            const int auxsocket = socket(remote_sockaddr_in->sin_family, SOCK_STREAM, IPPROTO_TCP);
            {
                // 5.6.1 bind hints
                bind(auxsocket, (struct sockaddr*)source_sockaddr_in, sizeof(struct sockaddr_in));

                // 5.6.2  get the assigned port
                socklen_t source_sockaddr_in_len = sizeof(struct sockaddr_in);
                getsockname(auxsocket, (struct sockaddr*)source_sockaddr_in, &source_sockaddr_in_len);
            }

            // 5.7 send the packet
            struct timespec time_start;
            {
                // 5.7.1 construct the packet and send
                char packet[sizeof(struct tcphdr) + sizeof(struct ip) + 1];
                struct ip* ipheader = (struct ip*)packet;
                struct tcphdr* tcpheader = (struct tcphdr*)(packet + sizeof(struct ip));
                fill_sync_packet(packet, source_sockaddr_in, remote_sockaddr_in);
                if (sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0, (struct sockaddr*)remote_sockaddr_in, sizeof(struct sockaddr_in)) == -1) {
                    fprintf(stderr, "%s: ", arguments.remotes[j].host);
                    perror("sendto");
                    continue;
                }

                // 5.7.2 get time
                clock_gettime(CLOCK_MONOTONIC, &time_start);

                // 5.7.3 verbose output
                if (verbose) {
                    static const int ip_presentation_length = 100;
                    char ip_presentation[ip_presentation_length];
                    printf("(sent) source=%s ip_len=%u th_seq=%u th_ack=%u th_flags=%u th_sport=%d th_dport=%u\n",
                           inet_ntop(source_sockaddr_in->sin_family, &ipheader->ip_src.s_addr, ip_presentation, ip_presentation_length),
                           ntohs(ipheader->ip_len),
                           ntohl(tcpheader->th_seq),
                           ntohl(tcpheader->th_ack),
                           tcpheader->th_flags,
                           ntohs(tcpheader->th_sport),
                           ntohs(tcpheader->th_dport));
                }
            }

            // 5.8 receive response
            struct timespec time_end = {0, 0};
            while (1) {
                // 5.8.1 recvfrom target
                static const int buffer_size = 65536;
                char packet[buffer_size];
                struct ip* ipheader = (struct ip*)packet;
                struct tcphdr* tcpheader = (struct tcphdr*)(packet + sizeof(struct ip));
                if (recvfrom(rawsocket, packet, buffer_size, 0, NULL, NULL) == -1) {
                    // 5.8.1.1 timeout => skip
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }

                    // 5.8.1.2 active reject
                    // 5.8.1.2.1 loose => take it
                    if (loose) {
                        clock_gettime(CLOCK_MONOTONIC, &time_end);
                        if (verbose) {
                            static const int ip_presentation_length = 100;
                            char ip_presentation[ip_presentation_length];
                            printf("(rejt) source=%s error=%s\n",
                                   inet_ntop(source_sockaddr_in->sin_family, &remote_sockaddr_in->sin_addr, ip_presentation, ip_presentation_length),
                                   strerror(errno));
                        }
                        break;
                    }

                    // 5.8.1.2.1 otherwise => print it and wait for next
                    else {
                        fprintf(stderr, "%s: ", arguments.remotes[j].host);
                        perror("recvfrom");
                        continue;
                    }
                }

                // 5.8.2 packet is a response => get time
                if (tcpheader->th_dport == source_sockaddr_in->sin_port) {
                    clock_gettime(CLOCK_MONOTONIC, &time_end);
                }

                // 5.8.3 verbose output
                if (verbose) {
                    static const int ip_presentation_length = 100;
                    char ip_presentation[ip_presentation_length];
                    printf("(recv) source=%s size=%u th_seq=%u th_ack=%u th_flags=%u th_sport=%d th_dport=%u\n",
                           inet_ntop(source_sockaddr_in->sin_family, &ipheader->ip_src.s_addr, ip_presentation, ip_presentation_length),
                           ntohs(ipheader->ip_len),
                           ntohl(tcpheader->th_seq),
                           ntohl(tcpheader->th_ack),
                           tcpheader->th_flags,
                           ntohs(tcpheader->th_sport),
                           ntohs(tcpheader->th_dport));
                }

                // 5.8.4 packet is a response => break
                if (tcpheader->th_dport == source_sockaddr_in->sin_port) {
                    break;
                }
            }

            // 5.9 clean up
            close(rawsocket);
            close(auxsocket);

            // 5.10 take stat
            if (time_end.tv_sec != 0) {
                stat[j][i] = (time_end.tv_sec - time_start.tv_sec) * 1000 + (double)(time_end.tv_nsec - time_start.tv_nsec) / 1000000;
            }
            else {
                stat[j][i] = 0;
            }

            // 5.11 verbose output
            if (verbose) {
                printf("(conn) %s round-trip time = %.2fms\n", arguments.remotes[j].host, stat[j][i]);
            }

            // 5.12 throttle
            {
                struct timespec time_remainder;
                clock_gettime(CLOCK_MONOTONIC, &time_remainder);
                time_remainder.tv_sec = throttle.tv_sec - (time_remainder.tv_sec - time_start.tv_sec);
                time_remainder.tv_nsec = throttle.tv_nsec - (time_remainder.tv_nsec - time_start.tv_nsec);
                if (time_remainder.tv_nsec < 0) {
                    time_remainder.tv_nsec += 1000000000;
                    time_remainder.tv_sec -= 1;
                }
                if (time_remainder.tv_sec >= 0) {
                    nanosleep(&time_remainder, NULL);
                }
            }
        }
    }

    // 6. print stat
    for (i = 0; i < arguments.remotes_count; i++) {
        printf("%s\t:", arguments.remotes[i].host);
        for (j = 0; j < arguments.count; j++) {
            if (stat[i][j]) {
                printf(" %.2f", stat[i][j]);
            }
            else {
                printf(" -");
            }
        }
        printf("\n");
    }

    return 0;
}
