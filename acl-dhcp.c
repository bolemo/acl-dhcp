#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

typedef struct my_socket {
    int sock;
    struct sockaddr_ll addr;
} my_socket_t;

void my_socket_init(my_socket_t *ms, int proto, char *dev, u_int8_t promiscuous) {
    int p=htons(proto);
    ms->sock = socket (AF_PACKET, SOCK_RAW, p);
    // Get the index of the interface
    struct ifreq if_idx; memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(ms->sock, SIOCGIFINDEX, &if_idx) < 0) perror("SIOCGIFINDEX");
    ms->addr.sll_family = AF_PACKET;
    ms->addr.sll_ifindex = if_idx.ifr_ifindex;    // Index of the network device
    ms->addr.sll_halen = ETH_ALEN;                // Address length
    ms->addr.sll_protocol = p;
    if (promiscuous) { // if used MAC is different from interface MAC
        struct packet_mreq mreq = {0};
        mreq.mr_ifindex = if_idx.ifr_ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(ms->sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) { perror("setsockopt"); exit(1); }
    }
}

void my_socket_send_packet_to(my_socket_t *ms, u_int8_t *packet, int len, u_int8_t *dmac) {
    memcpy(&ms->addr.sll_addr, dmac, 6);         // Destination MAC
    int result = sendto (ms->sock, packet, len, 0, (struct sockaddr*)&ms->addr, sizeof(struct sockaddr_ll));
    if (result <= 0) { perror("sendto failed"); exit(1); }
}

//
//  DHCP-CLIENT -->
//

typedef struct dhcp_frame {
    u_int8_t    opcode;
    u_int8_t    htype;
    u_int8_t    hlen;
    u_int8_t    hops;
    u_int32_t   xid;
    u_int16_t   secs;
    u_int16_t   flags;
    u_int32_t   ciaddr;
    u_int32_t   yiaddr;
    u_int32_t   siaddr;
    u_int32_t   giaddr;
    u_int8_t    chaddr[16];
    char        sname[64];
    char        file[128];
    uint32_t    magic_cookie;
    u_int8_t    options[0];
} dhcp_frame_t;

#define DHCP_BOOTREQUEST                  1
#define DHCP_BOOTREPLY                    2

#define DHCP_HTYPE_ETHERNET_10MB          1

#define DHCP_OPTION_PAD                   0
#define DHCP_OPTION_SUBNET_MASK           1
#define DHCP_OPTION_ROUTER                3
#define DHCP_OPTION_DOMAIN_SERVER         6
#define DHCP_OPTION_DOMAIN_NAME          15
#define DHCP_OPTION_ADDRESS_REQUEST      50
#define DHCP_OPTION_ADDRESS_TIME         51
#define DHCP_OPTION_MSG_TYPE             53
#define DHCP_OPTION_SERVER_ID            54
#define DHCP_OPTION_PARAMETER_LIST       55
#define DHCP_OPTION_RENEWAL_TIME         58
#define DHCP_OPTION_REBINDING_TIME       59
#define DHCP_OPTION_CLIENT_ID            61
#define DHCP_OPTION_END                 255

#define DHCP_MESSAGE_TYPE_DISCOVER        1
#define DHCP_MESSAGE_TYPE_OFFER           2
#define DHCP_MESSAGE_TYPE_REQUEST         3
#define DHCP_MESSAGE_TYPE_DECLINE         4
#define DHCP_MESSAGE_TYPE_ACK             5
#define DHCP_MESSAGE_TYPE_NAK             6
#define DHCP_MESSAGE_TYPE_RELEASE         7

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_MAGIC_COOKIE   0x63825363

#define DHCP_CLIENT_INIT       0
#define DHCP_CLIENT_SELECTING  1
#define DHCP_CLIENT_REQUESTING 2
#define DHCP_CLIENT_RENEWING   3
#define DHCP_CLIENT_REBINDING  4
#define DHCP_CLIENT_BOUND      5

#define DHCP_ASK_DISCOVERY     1
#define DHCP_ASK_REQUEST       2
#define DHCP_ASK_RENEW         3
#define DHCP_ASK_REBIND        4
#define DHCP_ASK_RELEASE       0

typedef struct dhcp_client {
    char *dev;
    u_int8_t mac[6];
    u_int8_t timeout;
    u_int32_t xid;
    u_int32_t ip;
    u_int32_t server_ip;
    u_int8_t server_mac[6];
    u_int32_t router_ip;
    unsigned int lease_duration;
    unsigned int renewal_duration;
    unsigned int rebinding_duration;
    time_t lease_start_time;
    u_int8_t last_asked;
    u_int8_t last_msg_type;
    u_int8_t status;
} dhcp_client_t;

typedef struct dhcp_msg {
    u_int8_t type;
    time_t rtime;
    u_int8_t server_mac[6];
    u_int32_t client_ip;
    u_int32_t server_ip;
    u_int32_t router_ip;
    u_int32_t relay_ip;
    u_int32_t subnet_mask;
    u_int32_t address_time;
    u_int32_t renewal_time;
    u_int32_t rebinding_time;
} dhcp_msg_t;

// GLOBALS
static dhcp_client_t dhcp_client;
my_socket_t dhcp_sock;

u_int8_t dhcp_client_status() {
    if (dhcp_client.status<DHCP_CLIENT_RENEWING) return dhcp_client.status;
    time_t now=time(NULL);
    if (now>dhcp_client.lease_start_time+dhcp_client.lease_duration)
        dhcp_client.status=DHCP_CLIENT_INIT;
    else if (now>dhcp_client.lease_start_time+dhcp_client.rebinding_duration)
        dhcp_client.status=DHCP_CLIENT_REBINDING;
    else if (now>dhcp_client.lease_start_time+dhcp_client.renewal_duration)
        dhcp_client.status=DHCP_CLIENT_RENEWING;
    return dhcp_client.status;
}

u_int8_t dhcp_alarm_triggered=0;
void dhcp_alarm_timeout(int sig) {
    dhcp_alarm_triggered=1;
}

// Return checksum for the given data.
static unsigned short in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

static void get_dhcp_options(u_int8_t *frame, dhcp_msg_t *dhcp_msg) {
    u_int8_t cur_index, cur_len;
    for (cur_index=0; (cur_len = frame[cur_index + 1]); cur_index += cur_len + 2) switch (frame[cur_index]) {
        case DHCP_OPTION_SUBNET_MASK:
            dhcp_msg->subnet_mask = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_ROUTER:
            dhcp_msg->router_ip = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_ADDRESS_TIME:
            dhcp_msg->address_time = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_RENEWAL_TIME:
            dhcp_msg->renewal_time = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_REBINDING_TIME:
            dhcp_msg->rebinding_time = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_MSG_TYPE:
            dhcp_msg->type = (u_int8_t)frame[cur_index + 2]; break;
        case DHCP_OPTION_SERVER_ID:
            dhcp_msg->server_ip = ntohl(*((u_int32_t*)&frame[cur_index + 2])); break;
        case DHCP_OPTION_END: return;
    }
    return;
}

u_int8_t dhcp_listen(u_char *arg) {
    dhcp_alarm_triggered=0;
    signal(SIGALRM, dhcp_alarm_timeout);
    alarm(dhcp_client.timeout);
    
    unsigned char frame[4096];
    struct ether_header *eframe;
    struct ip *ip_frame;
    struct udphdr *udp_frame;
    dhcp_frame_t *dhcp_frame;
    u_int loop=1;

    do {
        if (recv(dhcp_sock.sock,frame,4096,0) < 0) { perror("ERROR: recv"); exit(1); }  // ERROR
        if (dhcp_alarm_triggered) return 0;                                             // TIMED OUT
        
        eframe = (struct ether_header *)frame;
        if (htons(eframe->ether_type) != ETHERTYPE_IP) continue;        // we want an IP frame
    
        ip_frame = (struct ip *)(frame + sizeof(struct ether_header));
        if (ip_frame->ip_p != IPPROTO_UDP) continue;                    // we want UDP
    
        udp_frame = (struct udphdr *)((char *)ip_frame + sizeof(struct ip));
        if (ntohs(udp_frame->uh_sport) != DHCP_SERVER_PORT) continue;   // we want from DHCP server
    
        dhcp_frame = (dhcp_frame_t *)((char *)udp_frame + sizeof(struct udphdr));
        if (dhcp_frame->opcode != DHCP_BOOTREPLY) continue;             // we want a DHCP BOOTREPLY message
    
        if ((memcmp(dhcp_client.mac, dhcp_frame->chaddr, sizeof(dhcp_client.mac)) != 0) || (dhcp_frame->xid != ntohl(dhcp_client.xid))) continue;                          // we want the DHCP message to be addressed to the client
        loop=0;
    } while (loop);
    
    alarm(0);

    // FROM HERE, WE KNOW WE GOT A VALID RESPONSE FROM THE SERVER
    dhcp_msg_t *msg_p = (dhcp_msg_t*)arg;
    get_dhcp_options(dhcp_frame->options, msg_p);       // Get the DHCP options
    msg_p->rtime = time(NULL);                          // Get time we received the message
    memcpy(msg_p->server_mac, eframe->ether_shost, 6);  // Get the Server MAC
    msg_p->client_ip = ntohl(dhcp_frame->yiaddr);       // Get the Client IP
    msg_p->relay_ip = ntohl(dhcp_frame->giaddr);        // Get the Relay Agent IP
    
    return 1;   // OK
}

#define DHCP_SEND_BROADCAST 0
#define DHCP_SEND_UNICAST   1
void dhcp_send(u_int8_t *options, u_int8_t opt_len, u_int8_t cast) {
    static const u_int8_t bmac[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t *dmac;
    if (cast==DHCP_SEND_UNICAST) dmac=(u_int8_t *)dhcp_client.server_mac;
    else dmac=(u_int8_t *)&bmac;
    
    int len = 0;
    u_char packet[4096];
    struct udphdr *udp_header;
    struct ip *ip_header;
    dhcp_frame_t *dhcp_frame;

    struct ether_header *eframe = (struct ether_header *)packet;
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
    dhcp_frame = (dhcp_frame_t *)(((char *)udp_header) + sizeof(struct udphdr));

    // Build DHCP layer
    memset(dhcp_frame, 0, sizeof(dhcp_frame_t));
    len += sizeof(dhcp_frame_t);
    dhcp_frame->opcode = DHCP_BOOTREQUEST;
    dhcp_frame->htype = DHCP_HTYPE_ETHERNET_10MB;
    dhcp_frame->hlen = 6;
    memset(&dhcp_frame->chaddr[6], 0, sizeof(u_int8_t)*10);
    memcpy(dhcp_frame->chaddr, dhcp_client.mac, sizeof(u_int8_t)*6);
    dhcp_frame->xid = htonl(dhcp_client.xid);
    if (cast==DHCP_SEND_UNICAST) dhcp_frame->ciaddr = htonl(dhcp_client.ip);
    dhcp_frame->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    memcpy(dhcp_frame->options, options, opt_len);
    len += opt_len;
    
    // Build UDP layer
    if (len & 1) len += 1;
    len += sizeof(struct udphdr);
    udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
    udp_header->uh_dport = htons(DHCP_SERVER_PORT);
    udp_header->uh_ulen = htons(len);
    udp_header->uh_sum = 0;
    
    // Build IP layer
    len += sizeof(struct ip);
    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = 0x10;
    ip_header->ip_len = htons(len);
    ip_header->ip_id = htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    if (cast==DHCP_SEND_UNICAST) {
        ip_header->ip_src.s_addr = htonl(dhcp_client.ip);
        ip_header->ip_dst.s_addr = htonl(dhcp_client.server_ip);
    } else { // DHCP_SEND_BROADCAST
        ip_header->ip_src.s_addr = 0;
        ip_header->ip_dst.s_addr = 0xFFFFFFFF;
    }
    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));
    
    // Build ethernet layer
    memcpy(eframe->ether_shost, dhcp_client.mac, 6);
    memcpy(eframe->ether_dhost, dmac, 6);
    eframe->ether_type = htons(ETHERTYPE_IP);

    len += sizeof(struct ether_header);

    // send the packet
    my_socket_send_packet_to(&dhcp_sock, packet, len, dmac);
}

void dhcp_option_add(u_int8_t *options, unsigned int *pos, u_int8_t code, u_int8_t *data, u_int8_t len) {
    options[*pos] = code;
    options[*pos+1] = len;
    memcpy(&options[*pos+2], data, len);
    *pos+= len + 2;
}

void dhcp_option_add_msg_type(u_int8_t *options, unsigned int *pos, u_int8_t msg_type) {
    options[(*pos)++] = DHCP_OPTION_MSG_TYPE;
    options[(*pos)++] = 1;
    options[(*pos)++] = msg_type;
}

void dhcp_option_end(u_int8_t *options, unsigned int *pos) {
    options[(*pos)++] = DHCP_OPTION_END;
}

u_int8_t dhcp_do(u_int8_t ask) {
//    int result;
    u_int8_t options[32];
    unsigned int pos=0;
    u_int8_t cast;
    dhcp_client.last_asked=ask;
    switch (ask) {
        case DHCP_ASK_DISCOVERY:
            dhcp_client.status=DHCP_CLIENT_SELECTING;
            dhcp_client.last_msg_type=DHCP_MESSAGE_TYPE_DISCOVER;
            cast=DHCP_SEND_BROADCAST;
            dhcp_option_add_msg_type(options, &pos, DHCP_MESSAGE_TYPE_DISCOVER);
            dhcp_option_add(options, &pos, DHCP_OPTION_CLIENT_ID, (u_int8_t *)dhcp_client.mac, 6);
            break;
        case DHCP_ASK_REQUEST: {
            dhcp_client.status=DHCP_CLIENT_REQUESTING;
            dhcp_client.last_msg_type=DHCP_MESSAGE_TYPE_REQUEST;
            cast=DHCP_SEND_BROADCAST;
            dhcp_option_add_msg_type(options, &pos, DHCP_MESSAGE_TYPE_REQUEST);
            dhcp_option_add(options, &pos, DHCP_OPTION_CLIENT_ID, (u_int8_t *)dhcp_client.mac, 6);
            u_int32_t data = htonl(dhcp_client.ip);
            dhcp_option_add(options, &pos, DHCP_OPTION_ADDRESS_REQUEST, (u_int8_t *)&data, sizeof(u_int32_t));
            data = htonl(dhcp_client.server_ip);
            dhcp_option_add(options, &pos, DHCP_OPTION_SERVER_ID, (u_int8_t *)&data, sizeof(u_int32_t));
            u_int8_t list[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER, DHCP_OPTION_ADDRESS_TIME, DHCP_OPTION_RENEWAL_TIME, DHCP_OPTION_REBINDING_TIME};
            dhcp_option_add(options, &pos, DHCP_OPTION_PARAMETER_LIST, (u_int8_t *)list, sizeof(list));
            break; }
        case DHCP_ASK_RENEW: {
            dhcp_client.status=DHCP_CLIENT_RENEWING;
            dhcp_client.last_msg_type=DHCP_MESSAGE_TYPE_REQUEST;
            cast=DHCP_SEND_UNICAST;
            dhcp_option_add_msg_type(options, &pos, DHCP_MESSAGE_TYPE_REQUEST);
            u_int8_t list[] = {DHCP_OPTION_ROUTER, DHCP_OPTION_ADDRESS_TIME, DHCP_OPTION_RENEWAL_TIME, DHCP_OPTION_REBINDING_TIME};
            dhcp_option_add(options, &pos, DHCP_OPTION_PARAMETER_LIST, (u_int8_t *)list, sizeof(list));
            dhcp_option_add(options, &pos, DHCP_OPTION_CLIENT_ID, (u_int8_t *)dhcp_client.mac, 6);
            break; }
    }
    dhcp_option_end(options, &pos);
        
    dhcp_send(options, pos, cast);
    
    /* GET/WAIT FOR ANSWER */
    dhcp_msg_t dhcp_msg;
    memset(&dhcp_msg, 0, sizeof(dhcp_msg_t));
    if (!dhcp_listen((u_char*)&dhcp_msg)) return 0; // TIMED OUT
    
    // ANWSER RECEIVED
    dhcp_client.last_msg_type=dhcp_msg.type;
    switch (dhcp_msg.type) {
        case DHCP_MESSAGE_TYPE_OFFER:
            dhcp_client.ip = dhcp_msg.client_ip;
            dhcp_client.server_ip = dhcp_msg.server_ip;
            memcpy(dhcp_client.server_mac, dhcp_msg.server_mac, sizeof(dhcp_client.server_mac));
            break;
        case DHCP_MESSAGE_TYPE_ACK:
            dhcp_client.ip = dhcp_msg.client_ip;
            dhcp_client.router_ip = dhcp_msg.router_ip;
            dhcp_client.lease_start_time=dhcp_msg.rtime;
            dhcp_client.lease_duration=dhcp_msg.address_time;
            dhcp_client.renewal_duration=(dhcp_msg.renewal_time)?dhcp_msg.renewal_time:(dhcp_msg.address_time/2);
            dhcp_client.rebinding_duration=(dhcp_msg.rebinding_time)?dhcp_msg.rebinding_time:(dhcp_msg.address_time*7/8);
            dhcp_client.status=DHCP_CLIENT_BOUND;
            break;
        case DHCP_MESSAGE_TYPE_NAK:
        	dhcp_client.lease_duration=0;
        	dhcp_client.renewal_duration=0;
            dhcp_client.rebinding_duration=0;
            dhcp_client.status=DHCP_CLIENT_INIT;
            break;
    }
    
    return dhcp_client.status;
}

u_int8_t dhcp_get_lease() {
    u_int8_t status=0;
    if (dhcp_client_status() < DHCP_CLIENT_RENEWING) {
        if ((status = dhcp_do(DHCP_ASK_DISCOVERY))) status = dhcp_do(DHCP_ASK_REQUEST);
    } else {
        status = dhcp_do(DHCP_ASK_RENEW);
    }
    return status;
}

#define DHCP_DEFAULT_TIMEOUT 10
void dhcp_init(char *dev, u_int8_t *mac, u_int8_t timeout, u_int8_t promiscuous) {
    srand(time(NULL));
    memset(&dhcp_client, 0, sizeof(dhcp_client_t));
    dhcp_client.xid=random();
    dhcp_client.dev=dev;
    dhcp_client.timeout=(timeout)?timeout:DHCP_DEFAULT_TIMEOUT;
    memcpy(dhcp_client.mac, mac, 6);
    
    my_socket_init(&dhcp_sock, ETHERTYPE_IP, dev, promiscuous);
}

//
// <-- DHCP CLIENT
//

//
// ARP PING -->
//

#define ARP_REQUEST 1
#define ARP_REPLY   2

// MAC header
#define FRAME_MAC_DST     0
#define FRAME_MAC_SRC     6
#define FRAME_ETHERTYPE  12
// ARP header
#define FRAME_ARP_HTYPE  14
#define FRAME_ARP_PTYPE  16
#define FRAME_ARP_HLEN   18
#define FRAME_ARP_PLEN   19
#define FRAME_ARP_OPER   20
// ARP message
#define FRAME_ARP_SHA    22
#define FRAME_ARP_SPA    28
#define FRAME_ARP_THA    32
#define FRAME_ARP_TPA    38

#define ARP_SEND_BROADCAST 0
#define ARP_SEND_UNICAST   1

#define ARP_TIMEOUT 5

typedef struct arp_ping_args {
    u_int8_t    smac[6];
    u_int32_t   sip;
    u_int8_t    dmac[6];
    u_int32_t   dip;
    u_int8_t    mode;   // UNICAST or BROADCAST
} arp_ping_args_t;

my_socket_t arp_sock;

void arp_ping_init(char *dev, u_int8_t promiscuous) {
    my_socket_init(&arp_sock, ETHERTYPE_ARP, dev, promiscuous);
}

u_int8_t arp_alarm_triggered=0;
void arp_alarm_timeout(int sig) {
    arp_alarm_triggered=1;
}

static void arp_send_request(arp_ping_args_t *args) {
    u_int8_t packet[42];
    static const u_int8_t bmac[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t *dmac;
    if (args->mode==ARP_SEND_UNICAST) dmac=(u_int8_t *)&args->dmac;
    else dmac=(u_int8_t *)&bmac;
    
    // build ethernet header
    memcpy(&packet[FRAME_MAC_DST], dmac, 6);
    memcpy(&packet[FRAME_MAC_SRC], &args->smac, 6);
    *(u_int16_t *)&packet[FRAME_ETHERTYPE]=htons(ETHERTYPE_ARP);
    
    // build arp header
    *(u_int16_t *)&packet[FRAME_ARP_HTYPE]=htons(0x01);
    *(u_int16_t *)&packet[FRAME_ARP_PTYPE]=htons(0x0800);
    *(u_int8_t *)&packet[FRAME_ARP_HLEN]=6;
    *(u_int8_t *)&packet[FRAME_ARP_PLEN]=4;
    *(u_int16_t *)&packet[FRAME_ARP_OPER]=htons(ARP_REQUEST);
    
    // build arp message
    memcpy(&packet[FRAME_ARP_SHA], &args->smac, 6);
    *(u_int32_t *)&packet[FRAME_ARP_SPA]=htonl(args->sip);
    memcpy(&packet[FRAME_ARP_THA], dmac, 6);
    *(u_int32_t *)&packet[FRAME_ARP_TPA]=htonl(args->dip);
    
    // send the packet
    my_socket_send_packet_to(&arp_sock, packet, sizeof(packet), dmac);
}

u_int8_t arp_listen(u_char *args) {
    arp_alarm_triggered=0;
    signal(SIGALRM, arp_alarm_timeout);
    alarm(ARP_TIMEOUT);
    
    u_int32_t   tpa = htonl(((arp_ping_args_t *)args)->sip),
                spa = htonl(((arp_ping_args_t *)args)->dip);
    
    unsigned char frame[128];
    
    do {
        if (recv(arp_sock.sock,frame,128,0) < 0) { perror("ERROR: recv"); exit(1); }    // ERROR
        if (arp_alarm_triggered) return 0;                                              // TIMED OUT
    }
    while (!(   (*(u_int16_t *)&frame[FRAME_ETHERTYPE] == htons(ETHERTYPE_ARP)) // we want an ARP frame
        && (*(u_int16_t *)&frame[FRAME_ARP_OPER] == htons(ARP_REPLY))           // we want an ARP reply
        && (memcmp(&frame[FRAME_ARP_SPA], &spa, 4) == 0)                        // we want reply from gateway
        && (memcmp(&frame[FRAME_ARP_TPA], &tpa, 4) == 0) ));                    // we want reply to us
    
    alarm(0);
    return 1;
}

u_int8_t arp_ping(arp_ping_args_t *args) {
    
    // ARP Request
    arp_send_request(args);
    
    // ARP Reply
//    arp_alarm_triggered=0;
//    signal(SIGALRM, arp_alarm_timeout);
//    alarm(ARP_TIMEOUT);
    return arp_listen((u_char *)args);
//    alarm(0);
    
//    return (!arp_alarm_triggered);
}

//
// <-- ARP PING
//

#define MAC_SF "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_I(M) M[0], M[1], M[2], M[3], M[4], M[5]
#define IP_SF "%u.%u.%u.%u"
#define IP_I(IP) IP >> 24, ((IP << 8) >> 24), (IP << 16) >> 24, (IP << 24) >> 24
static const char *DHCP_CLIENT[] = {
    "INIT", "SELECTING", "REQUESTING", "RENEWING", "REBINDING", "BOUND"
};
static const char *DHCP_CLIENT_LAST_MSG_TYPE[] = {
    NULL, "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE"
};
static const char *DHCP_CLIENT_ASKED[] = {
    "RELEASE", "DISCOVERY", "REQUEST", "RENEW", "REBIND"
};
/*
static void print_dhcp_client(dhcp_client_t *dhcpc) {
    printf("Client MAC: "MAC_SF"\n", MAC_I(dhcpc->mac));
    printf("Client timeout: %u\n", dhcpc->timeout);
    printf("Client device: %s\n", dhcpc->dev);
    printf("XID: %06x\n", dhcpc->xid);
    printf("Client IP: "IP_SF"\n", IP_I(dhcpc->ip));
    printf("Server IP: "IP_SF"\n", IP_I(dhcpc->server_ip));
    printf("Server MAC: "MAC_SF"\n", MAC_I(dhcpc->server_mac));
//    struct tm *tm_ls = localtime(&dhcpc->lease_expiration_time);
//    char tstr[19];
//    strftime(tstr, 26, "%Y-%m-%d %H:%M:%S", tm_ls);
//    printf("DHCP Lease expiration: %s\n", tstr);
    printf("DHCP Status: %s\n", DHCP_CLIENT[dhcpc->status]);
}

static void print_dhcp_msg(dhcp_msg_t *dhcpm) {
    printf("DHCP Message Type: %i\n",dhcpm->type);
    struct tm *tm_ls = localtime(&dhcpm->rtime);
    char tstr[19];
    strftime(tstr, 26, "%Y-%m-%d %H:%M:%S", tm_ls);
    printf("DHCP Message Received: %s\n",tstr);
    printf("Server MAC: "MAC_SF"\n", MAC_I(dhcpm->server_mac));
    printf("Client IP: "IP_SF"\n", IP_I(dhcpm->client_ip));
    printf("Server IP: "IP_SF"\n", IP_I(dhcpm->server_ip));
    printf("Router IP: "IP_SF"\n", IP_I(dhcpm->router_ip));
    printf("Relay Agent IP: "IP_SF"\n", IP_I(dhcpm->relay_ip));
    printf("Subnet Mask: "IP_SF"\n", IP_I(dhcpm->subnet_mask));
    printf("Lease Time: %u\n", dhcpm->address_time);
}
*/
//
// DHCP-ACL -->
//

#define SELF_NAME "acl-dhcp"

typedef struct acl_dhcp_arguments {
    u_int8_t if_flag;
    char iface[80];
    u_int8_t mac_flag;
    u_int8_t mac[6];
    u_int32_t router_ip;
    unsigned int renew_duration;
    u_int8_t promiscuous;
} acl_dhcp_arguments_t;
static acl_dhcp_arguments_t acl_dhcp_arguments;

unsigned int acl_dhcp_renew_duration() {
    return (acl_dhcp_arguments.renew_duration)?acl_dhcp_arguments.renew_duration:dhcp_client.renewal_duration;
}
u_int8_t acl_dhcp_renew() {
    return (time(NULL)>dhcp_client.lease_start_time+acl_dhcp_renew_duration());
}
u_int32_t acl_dhcp_router_ip() {
    return (acl_dhcp_arguments.router_ip)?acl_dhcp_arguments.router_ip:dhcp_client.router_ip;
}

void dolog(char *);

char *log_path="/var/log/"SELF_NAME".log";              // Log file path
int lmn=100;                                            // Log min lines
int lmx=150;                                            // Log max lines
char *pid_path="/var/run/"SELF_NAME".pid";              // PID file path
char *fifo_path="/tmp/"SELF_NAME".fifo";                // FIFO file path
static u_int8_t arp_status=0;

void usage() {
    printf("Usage: "SELF_NAME" [-i <interface>] [-m <MAC address>] [-r <DHCP renew interval in sec>] [-g <gateway IP address>] start|stop|restart|status|log\n");
}

int is_running() {
    FILE* file;
    int pid=0;
    if (!(file=fopen (pid_path, "r"))) return 0;
    fscanf (file, "%d", &pid);
    fclose (file);
    return (pid && (kill(pid,0)==0))?pid:0;
}

#define FIFO_LEN 250
void _info() {
    char str[FIFO_LEN];
    char mac_mode[15], router_mode[10], renew_mode[10];
    if (acl_dhcp_arguments.mac_flag) strcpy(mac_mode,"manual");
    else strcpy(mac_mode,"from interface");
    if (acl_dhcp_arguments.router_ip) strcpy(router_mode,"manual");
    else strcpy(router_mode,"from DHCP");
    if (acl_dhcp_arguments.renew_duration) strcpy(renew_mode,"manual");
    else strcpy(renew_mode,"from DHCP");
    sprintf(str,"| Interface: %s\n| MAC: "MAC_SF" (%s)\n| Gateway IP: "IP_SF" (%s)\n| ARP link to gateway: %s\n| DHCP renewal time interval: %i s (%s)\n| DHCP status: %s\n| DHCP offered IP: "IP_SF, dhcp_client.dev, MAC_I(dhcp_client.mac), mac_mode, IP_I(acl_dhcp_router_ip()), router_mode, (arp_status)?"OK":"KO", acl_dhcp_renew_duration(), renew_mode, DHCP_CLIENT[dhcp_client_status()], IP_I(dhcp_client.ip));
    int fifo = open(fifo_path, O_WRONLY);
    write(fifo, str, FIFO_LEN);
    close(fifo);
}
void info(int pid) {
    if (pid) {
        printf(SELF_NAME" is running with PID %i.\n", pid);
        char str[FIFO_LEN];
        mkfifo(fifo_path, 0666);
        kill(pid, SIGUSR1);
        int fifo = open(fifo_path, O_RDONLY|O_NONBLOCK);
        struct pollfd pwait = {.fd = fifo, .events = POLLIN};
        if (poll(&pwait, 1, 10 * 1000)) {
            read(fifo, str, FIFO_LEN);
            printf("%s\n",str);
        } else {
            fprintf(stderr, "Unable to get info from PID %i (fifo timed out).\n", pid);
        }
        close(fifo);
        remove(fifo_path);
    } else {
        printf(SELF_NAME" is not running\n");
    }
}

void cat(char *path) {
    FILE *file;
    int c;
    if ((file=fopen(path,"r"))) {
        while((c=fgetc(file))!=EOF) printf("%c",(char)c);
        fclose (file);
    }
    return;
}

void stop(int pid) {
    if (pid && !kill(pid, 15)) {
        int i=0;
        while (kill(pid, 0)==0) {
            sleep(1);
            if (++i > 20) { fprintf(stderr, "Unable to stop running "SELF_NAME" with PID %i; exiting!\n", pid); exit(1); }
        }
        printf(SELF_NAME" with PID %i stopped.\n", pid);
    } else {
        printf(SELF_NAME" is not running!\n");
    }
}

void trap(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            remove(pid_path);
            char str[80];
            sprintf(str,"DAEMON: exiting (pid: %i)", getpid());
            dolog(str);
            exit(0);
            break;
        case SIGUSR1:
            _info();
            break;
    }
}

void dolog(char *lstr) {
    static FILE *file;
    if ((file=fopen(log_path,"a"))) {
        static char tstr[100];
        time_t now = time(NULL);
        strftime (tstr, 100, "%F %T", localtime (&now));
        fprintf(file, "%s, %s\n", tstr, lstr);
        fclose(file);
    }
    return;
}

void trimlog() {
    #define BUFF_SIZE 255
    FILE *file, *tmpfile;

    if ((file=fopen(log_path,"r"))) {
        int nl = 0, needtotrim=0;
        long int pos, refpos=0;
        char buff[BUFF_SIZE];
        fseek(file, 0, SEEK_END);
        pos = ftell(file);
        while (pos) {
            fseek(file, --pos, SEEK_SET);
            if ((fgetc(file) == '\n')) {
                if (nl++ == lmn) refpos=pos+1;
                if (nl >= lmx) {
                    needtotrim=1;
                    break;
                }
            }
        }
        char tmppath[strlen(log_path)+4];
        if (needtotrim) {
            strcpy(tmppath, log_path);
            strcat(tmppath, ".old");
            fseek(file, refpos, SEEK_SET);
            if ((tmpfile=fopen(tmppath,"w"))) {
                while (fgets(buff, sizeof(buff), file)) fputs(buff, tmpfile);
                fclose (tmpfile);
                fclose (file);
                rename(tmppath, log_path);
            } else fclose (file);
        } else fclose (file);
    }
}

void daemon_loop() { // This is the daemon
    signal(SIGQUIT,&trap); signal(SIGTERM,&trap); signal(SIGTERM,&trap);
    signal(SIGUSR1,&trap);
    dhcp_init(acl_dhcp_arguments.iface, (u_int8_t *)&acl_dhcp_arguments.mac, 10, acl_dhcp_arguments.promiscuous);
    arp_ping_init(acl_dhcp_arguments.iface, acl_dhcp_arguments.promiscuous);
    static arp_ping_args_t arp_args;
    memcpy(&arp_args.smac, &dhcp_client.mac, 6);
    chdir("/tmp");
    
    while(1) {
        trimlog();
        char str[80];
        // DHCP ACTION
        dhcp_get_lease();
        u_int8_t dhcp_status = dhcp_client_status();
        sprintf(str, "DHCP: %s(%s/%s)",DHCP_CLIENT[dhcp_status],DHCP_CLIENT_ASKED[dhcp_client.last_asked],DHCP_CLIENT_LAST_MSG_TYPE[dhcp_client.last_msg_type]);
        dolog(str);
        if (dhcp_status!=DHCP_CLIENT_BOUND) continue; // back to while

        memcpy(&arp_args.dmac, &dhcp_client.server_mac, 6);
        arp_args.sip=dhcp_client.ip;
        arp_args.dip=acl_dhcp_router_ip();
        arp_args.mode=ARP_SEND_UNICAST;
        
		while (!acl_dhcp_renew()) {
            // CHECK WITH ARP IF GATEWAY IS REACHABLE
            if (!(arp_status=arp_ping(&arp_args))) {
                dolog("ARP: gateway is not responding to unicast request");
                arp_args.mode=ARP_SEND_BROADCAST;
                if (!(arp_status=arp_ping(&arp_args))) {
                    dolog("ARP: gateway is not responding to broadcast request");
                    break;
                }
            }
            sleep(10);
        }
    }
}

void start() {
    pid_t cpid;
    if ((cpid=fork())>0) { // PARENT
        FILE *file;
        if ((file=fopen(pid_path,"w"))) {
            fprintf (file, "%i", cpid);
            fclose (file);
        }
        char str[80];
        sprintf(str,"DAEMON: starting (pid %i)", cpid);
        dolog(str);
    } else if (cpid<0) { // ERROR FORKING
        exit(1);
    } else { // CHILD
        daemon_loop();
    }
}

void check_flags() {
    if (!acl_dhcp_arguments.if_flag) {
        fprintf(stderr, "Missing interface (-i argument missing)!\n");
        exit(1);
    }
    u_int8_t nok=0;
    
    u_int8_t im[6];
    char addr_path[120];
    FILE* file;
    sprintf(addr_path, "/sys/class/net/%s/address", acl_dhcp_arguments.iface);
    if ((file=fopen (addr_path, "r"))) {
        if (fscanf (file, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &im[0], &im[1], &im[2], &im[3], &im[4], &im[5]) != 6) nok=1;
        fclose (file);
    }
    
    if (!acl_dhcp_arguments.mac_flag) {
        printf("No MAC address provided, using MAC of %s.\n", acl_dhcp_arguments.iface);
        memcpy(&acl_dhcp_arguments.mac, &im, 6);
    } else {
        if (memcmp(&acl_dhcp_arguments.mac, &im, 6) != 0) {
            printf("The MAC address provided is different that the MAC of %s. Using promiscuous mode.\n", acl_dhcp_arguments.iface);
            acl_dhcp_arguments.promiscuous=1;
        }
    }
    
    if (nok) {
        fprintf(stderr, "Missing MAC address (-m argument missing or could not get it from given interface)!\n");
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    memset(&acl_dhcp_arguments, 0, sizeof(acl_dhcp_arguments_t));
    int pid=is_running();
    int argv0size = strlen(argv[0]);
    strncpy(argv[0], SELF_NAME, argv0size);
    
    int opt;
    while((opt = getopt(argc, argv, ":i:m:r:g:")) != -1) switch(opt) {
        case 'i':
            if (!optarg) break;
            char dev_path[80]="/sys/class/net/";
            strcat(dev_path,optarg);
            struct stat sb;
            if (stat(dev_path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
                strcpy(acl_dhcp_arguments.iface, optarg);
                acl_dhcp_arguments.if_flag=1;
            } else {
                fprintf(stderr,"Interface %s does not exist!\n",optarg);
                exit(1);
            }
            break;
        case 'm':
            if (!optarg) break;
            if (sscanf(optarg, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &acl_dhcp_arguments.mac[0], &acl_dhcp_arguments.mac[1], &acl_dhcp_arguments.mac[2], &acl_dhcp_arguments.mac[3], &acl_dhcp_arguments.mac[4], &acl_dhcp_arguments.mac[5]) != 6) {
                fprintf(stderr,"Invalid MAC: %s !\n", optarg);
                exit(1);
            }
            acl_dhcp_arguments.mac_flag=1;
            break;
        case 'r':
            if (!optarg) break;
            if (sscanf(optarg, "%u", &acl_dhcp_arguments.renew_duration) != 1) {
                fprintf(stderr,"Invalid time interval: %s !\n", optarg);
                exit(1);
            }
            break;
        case 'g':
            if (!optarg) break;
            u_int32_t gip=0;
            if (inet_pton(AF_INET, optarg, &gip)!=1) {
                fprintf(stderr,"Invalid IP address: %s !\n", optarg);
                exit(1);
            }
            if (gip) acl_dhcp_arguments.router_ip=ntohl(gip);
            break;
        case ':':
            fprintf(stderr, "Option %s needs a value\n", argv[optind-1]);
            exit(1);
        case '?':
            fprintf(stderr, "Unknown option: -%c\n", optopt);
            exit(1);
    }

    if (argv[optind] == NULL) {
        fprintf(stderr, "No argument was provided!\n");
        usage();
        exit(1);
    } else if (argv[optind+1] != NULL) {
        fprintf(stderr, "Too many arguments were provided!\n");
        usage();
        exit(1);
    }
    if (!strcmp(argv[optind], "status")) {         // STATUS
        info(pid);
        exit(pid);
    } else if (!strcmp(argv[optind], "start")) {   // START
        if (pid) { fprintf(stderr, SELF_NAME" is already running with PID %i!\n", pid); exit(1); }
        check_flags();
        printf("Starting "SELF_NAME".\n");
        start();
        exit(0);
    } else if (!strcmp(argv[optind], "stop")) {    // STOP
        stop(pid);
        exit(0);
    } else if (!strcmp(argv[optind], "restart")) { // RESTART
        check_flags();
        stop(pid);
        printf("Restarting "SELF_NAME".\n");
        sleep(1);
        start();
        exit(0);
    } else if (!strcmp(argv[optind], "log")) {     // LOG
        cat(log_path);
        exit(0);
    } else {                                       // --
        fprintf(stderr, "Unknown argument: %s\n", argv[optind]);
        usage();
        exit(1);
    }
    return(0);
}

//
// <-- DHCP-ACL
//
