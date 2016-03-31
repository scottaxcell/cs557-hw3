#include <iostream>
#include <vector>
#include <map>
#include <algorithm>

#include "fsniffer.h"

static std::map<size_t, std::vector<Flow>> finishedFlows;
static std::vector<Flow> flows;
static int num = 0; // number of flows to print, default 0 means print all flows
static unsigned long timeout_interval = 60; // flow interval
static unsigned long time_offset = 0; // time to wait to start capturing fata
static unsigned long runtime = 0; // total time to run for specified by user
static unsigned long first_timestamp = 0; // fist timestamp in capture
static unsigned long start_time = 0; // time to start capture based on runtime, offset, etc.
static unsigned long max_runtime = 0; // maximum runtime for capture based on offset, runtime, etc.
static int user_specified_time = 0; // did the use specify a runtime

//
// Format string for a nice output
//
std::string padString(std::string input, int size)
{
  std::string str(input);
  while (str.size() < size) {
    str += " ";
  }
  return str;
}

//
// Print output header
//
void printHeader()
{
  std::cout << padString("StartTime", 16)
  << padString("Proto", 6)
  << padString("SrcAddr", 16)
  << padString("Sport", 6)
  << padString("Dir", 4)
  << padString("DstAddr", 16)
  << padString("Dport", 6)
  << padString("TotPkts", 10)
  << padString("TotBytes", 10)
  << padString("State", 10)
  << "Dur\n";
}

//
// Move remainging flows to finishedFlows and print output
//
void cleanupAndPrint()
{
  for (auto &flow : flows) {
    size_t hashValue = flow.hashValue();
    finishedFlows[hashValue].push_back(flow);
  }
  printHeader();
  if (num == 0) {
    for (auto &kvp : finishedFlows) {
      for (auto &flow : kvp.second) {
        flow.print();
      }
    }
  } else {
    int i = 0;
    for (auto &kvp : finishedFlows) {
      for (auto &flow : kvp.second) {
        if (i < num) {
          flow.print();
          i++;
        } else {
          return;
        }
      }
    }
  }
}

//
// Print usage
//
void usage()
{
  std::cout << "Usage: ./fsniffer [-r filename] [-i interface] [-t time] [-o time_offset] [-N num] [-S secs]" << std::endl;
  exit(0);
}

//
// Parses the pcap packet and updates the flows datastructure
//
void handlePacket(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  /* packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const struct sniff_udp *udp;            /* The UDP header */
  const struct icmp *icmp;                /* The ICMP header */
  int size_ip = 0;
  int size_tcp = 0;

  //
  // handle timer
  //
  if (first_timestamp == 0) {
    // Initialize the timer
    first_timestamp = (u_long)pkthdr->ts.tv_sec;
    if (time_offset != 0)
      start_time = first_timestamp + time_offset;
    else
      start_time = first_timestamp;
    max_runtime = start_time + runtime;
    /*DEBUG*/fprintf(stdout, "Initialized first_timestamp =  %lu\n", first_timestamp);
    /*DEBUG*/fprintf(stdout, "Initialized max_runtime =      %lu\n", max_runtime);
    /*DEBUG*/fprintf(stdout, "Initialized start_time =       %lu\n", start_time);
  }

  // Check we're doing ok on time
  u_long curr_time = (u_long)pkthdr->ts.tv_sec;
  if (curr_time < start_time) {
    return;
  }
  if (user_specified_time == 1 && (curr_time > max_runtime)) {
    fprintf(stdout, "\nRuntime limit of %lu seconds reached, exiting..\n", runtime);
    cleanupAndPrint();
    exit(0);
  }

  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  Flow flow;
  flow.srcAddr = inet_ntoa(ip->ip_src);
  flow.dstAddr = inet_ntoa(ip->ip_dst);

  /* determine protocol */  
  switch(ip->ip_p) {
    case IPPROTO_TCP:
      /* define/compute tcp header offset */
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      flow.protocol = "TCP";
      flow.srcPort = ntohs(tcp->th_sport);
      flow.dstPort = ntohs(tcp->th_dport);

      break;
    case IPPROTO_UDP:
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
      flow.protocol = "UDP";
      flow.srcPort = ntohs(udp->uh_sport);
      flow.dstPort = ntohs(udp->uh_dport);
      break;
    case IPPROTO_ICMP:
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      flow.protocol = "ICMP";
      flow.srcPort = 0;
      flow.dstPort = 0;
      break;
    default:
      // ignore anything that doesn't have IP
      return;
  }

  auto flowItr = std::find_if(flows.begin(), flows.end(), flow);
  if (flowItr != flows.end()) {
    //
    // have an existing flow
    //
    auto &f = *flowItr;

    //
    // check flow interval time
    //
    u_long flow_time = (curr_time - f.startTime.tv_sec);
    /*DEBUG*/fprintf(stdout, "current flow time = %lu\n", flow_time);
    if (flow_time >= timeout_interval) {
      /*DEBUG*/fprintf(stdout, "end flow\n");
      size_t hashValue = f.hashValue();
      finishedFlows[hashValue].push_back(f);
      /*DEBUG*/fprintf(stdout, "before erase %lu\n", flows.size());
      flows.erase(flowItr);
      /*DEBUG*/fprintf(stdout, "after  erase %lu\n", flows.size());
      return;
    }

    //
    // increment packet counter
    //
    (f.totalPkts)++;

    //
    // increment total bytes
    //
    f.totalBytes += pkthdr->len;

    //
    // udpate duration
    //
    // TODO verify this is working, seems off
    struct timeval currentTimestamp;
    currentTimestamp.tv_sec = pkthdr->ts.tv_sec;
    currentTimestamp.tv_usec = pkthdr->ts.tv_usec;
    timersub(&currentTimestamp, &f.startTime, &f.dur);

    //
    // update direction
    //
    if (f.protocol == "ICMP" && f.isOppositeDirection(flow)) {
      f.dir = "<->";
    } else if (f.protocol == "UDP" && f.isOppositeDirection(flow)) {
      f.dir = "<->";
    } else if (f.protocol == "TCP") {
      u_char flags;
      int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
      if (size_payload > 0) {
        if (f.dir == "<-")
          f.dir = "<->";
        else if (flow.dir == "")
          f.dir = "->";
      } else if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        if (flags & TH_SYN) {
          if (f.dir == "<-")
            f.dir = "<->";
          else if (f.dir == "")
            f.dir = "->";
        } else if (flags & TH_SYN && flags & TH_ACK) {
          if (f.dir == "->")
            f.dir = "<->";
          else if (f.dir == "")
            f.dir = "<-";
        }
      }
    }

    //
    // update the state
    //
    if (f.protocol == "ICMP") {
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      f.state = std::to_string(icmp->icmp_type);
    } else if (f.protocol == "UDP") {
      // leave blank intentionally
    } else if (f.protocol == "TCP") {
      u_char flags;
      int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
      if (size_payload > 0)
        f.state = "EST";
      else if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        if (flags & TH_FIN)
          f.state = "FIN";
        else if (flags & TH_SYN)
          f.state = "SYN";
        else if (flags & TH_RST)
          f.state = "RST";
        else if (flags & TH_PUSH && f.state != "EST")
          f.state = "PSH";
        else if (flags & TH_SYN && flags & TH_ACK)
          f.state = "SYNACK";
        else if (flags & TH_URG)
          f.state = "URG";
      }
    }
  } else {
    //
    // brand new flow
    //

    //
    // set start time to current timestamp
    //
    struct timeval startTime;
    startTime.tv_sec = pkthdr->ts.tv_sec;
    startTime.tv_usec = pkthdr->ts.tv_usec;
    flow.startTime = startTime;

    //
    // initialize duration time
    //
    struct timeval dur;
    dur.tv_sec = 0;
    dur.tv_usec = 0;
    flow.dur = dur;

    //
    // initialize direction
    //
    if (flow.protocol == "UDP") {
      int size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
      if (size_payload > 0)
        flow.dir = "->";
      else
        flow.dir = "<-";
    } else if (flow.protocol == "TCP") {
      u_char flags;
      int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
      if (size_payload > 0)
        flow.dir = "->";
      else if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        if (flags & TH_FIN)
          flow.dir = "<-";
        else if (flags & TH_SYN)
          flow.dir = "->";
        else if (flags & TH_SYN && flags & TH_ACK)
          flow.dir = "<-";
      }
    } else if (flow.protocol == "ICMP") {
      flow.dir = "->";
    }

    //
    // initialize packet counter
    //
    flow.totalPkts = 1;

    //
    // initialize total bytes
    //
    flow.totalBytes = pkthdr->len;

    //
    // initialize the state
    //
    if (flow.protocol == "ICMP") {
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      flow.state = std::to_string(icmp->icmp_type);
    }
    else if (flow.protocol == "UDP") {
      flow.state = "";
    }
    else if (flow.protocol == "TCP") {
      u_char flags;
      if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        if (flags & TH_FIN)
          flow.state = "FIN";
        else if (flags & TH_SYN)
          flow.state = "SYN";
        else if (flags & TH_RST)
          flow.state = "RST";
        else if (flags & TH_PUSH)
          flow.state = "PSH";
        else if (flags & TH_SYN && flags & TH_ACK)
          flow.state = "SYNACK";
        else if (flags & TH_URG)
          flow.state = "URG";
      } else {
        flow.state = "";
      }
    }

    flows.push_back(flow);
  }
}

//
// Main
//
int main(int argc, char* argv[])
{
  std::string filename;
  std::string interface;

  if (argc == 1) {
    usage();
  }
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-h") == 0) {
      usage();
    } else if (strcmp(argv[i], "-r") == 0) {
      filename = argv[++i];
    } else if (strcmp(argv[i], "-i") == 0) {
      interface = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0) {
      user_specified_time = 1;
      runtime = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-o") == 0) {
      time_offset = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-N") == 0) {
      num = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-S") == 0) {
      timeout_interval = std::stoi(argv[++i]);
    } else {
      usage();
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE]; 
  char filter_exp[] = "ip";      /* filter expression [3] */
  struct bpf_program fp;         /* compiled filter program (expression) */
  bpf_u_int32 net = 0;           /* ip */

  if (filename.size()) {
    /* open capture device */
    pcap_t *pcap = pcap_open_offline(filename.c_str(), errbuf);

    /* compile the filter expression */
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(pcap, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    pcap_loop(pcap, /*all packets*/-1, handlePacket, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(pcap);
  
  } else if (interface.size()) {

  }

  cleanupAndPrint();

  return 0;
}
