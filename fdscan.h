#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <functional>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define SIZE_UDP        8               /* length of UDP header */    

/* UDP header */
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */
};

/* Flow object */
class Flow {
public:
  struct timeval startTime;
  std::string protocol;
  std::string srcAddr;
  std::string dstAddr;
  std::string dir; // direction
  int srcPort;
  int dstPort;
  unsigned int totalPkts;
  unsigned int totalBytes;
  std::string state;
  struct timeval dur; // duration

  Flow& operator=(const Flow& f) {
    startTime = f.startTime;
    protocol = f.protocol;
    srcAddr = f.srcAddr;
    dstAddr = f.dstAddr;
    dir = f.dir;
    srcPort = f.srcPort;
    dstPort = f.dstPort;
    totalPkts = f.totalPkts;
    totalBytes = f.totalBytes;
    state = f.state;
    dur = f.dur;
    return *this;
  }

  // determines Flow equality
  bool operator==(const Flow& f) {
    return ((protocol == f.protocol) &&
            ((srcAddr == f.srcAddr && srcPort == f.srcPort && dstAddr == f.dstAddr && dstPort == f.dstPort) ||
             (srcAddr == f.dstAddr && srcPort == f.dstPort && dstAddr == f.srcAddr && dstPort == f.srcPort)));
  }
  bool operator()(const Flow& f) {
    return ((protocol == f.protocol) &&
            ((srcAddr == f.srcAddr && srcPort == f.srcPort && dstAddr == f.dstAddr && dstPort == f.dstPort) ||
             (srcAddr == f.dstAddr && srcPort == f.dstPort && dstAddr == f.srcAddr && dstPort == f.srcPort)));
  }

  bool isOppositeDirection(const Flow& f) {
    return (srcAddr == f.dstAddr && srcPort == f.dstPort && dstAddr == f.srcAddr && dstPort == f.srcPort);
  }

  void print() {
    char buf[40];
    time_t t;
    struct tm *nowtm;
    t = startTime.tv_sec;
    nowtm = localtime(&t);
    strftime(buf, sizeof(buf), "%H:%M:%S", nowtm);
    std::string humanTime(buf);
    humanTime += "." + std::to_string(startTime.tv_usec);
    
    //std::cout << startTime.tv_sec << "." << startTime.tv_usec << " "
    std::cout << padString(humanTime, 16)
    << padString(protocol, 6)
    << padString(srcAddr, 16)
    << padString(std::to_string(srcPort), 6)
    << padString(dir, 4)
    << padString(dstAddr, 16)
    << padString(std::to_string(dstPort), 6)
    << padString(std::to_string(totalPkts), 10)
    << padString(std::to_string(totalBytes), 10)
    << padString(state, 10)
    << dur.tv_sec << "." << dur.tv_usec << std::endl;
  }
  std::string padString(std::string input, int size) {
    std::string str(input);
    while (str.size() < size) {
      str += " ";
    }
    return str;
  }

  size_t hashValue() {
    std::hash<std::string> hash_fn;
    std::hash<int> hash_fn2;
    size_t sa = hash_fn(srcAddr);
    size_t da = hash_fn(dstAddr);
    size_t sp = hash_fn2(srcPort);
    size_t dp = hash_fn2(dstPort);
    return (sa+da+sp+dp);
  }
};
  
// A scanner can be defined by two different behaviors
// Horizontal Scan: A horizontal scan is described as scan against a group of IP addresses over a single port. In other words, a scanner may be looking for all active web servers in a subnet, so it scans all IP addresses on port 80.
// Vertical Scan: A vertical scan is described as a single IP address being scanned for multiple live ports. For example, a scanner may scan all ports on a host looking for active services.

typedef std::vector<int> dstPorts_t;
typedef std::map<std::string, dstPorts_t> dstHosts_t;
class Scanner
{
public:
  std::string ip;
  std::string protocol;
  dstHosts_t dstHosts; //dstHosts[10.0.0.3] = [ 23, 24, 63]

  Scanner() {}

  Scanner(std::string &ip, std::string &protocol)
  : ip(ip), protocol(protocol)
  {}

  Scanner(const Scanner &s)
  : ip(s.ip), protocol(s.protocol)
  {}

  size_t hashValue() const {
    std::hash<std::string> hash_fn;
    size_t ipHash = hash_fn(ip);
    size_t protocolHash = hash_fn(protocol);
    return (ipHash + protocolHash);
  }

  bool operator==(const Scanner& s) const {
    return hashValue() == s.hashValue();
  }

  bool operator()(const Scanner& s) const {
    return hashValue() == s.hashValue();
  }

};

