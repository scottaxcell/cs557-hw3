#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <set>
#include "fdscan.h"

static std::map<size_t, std::vector<Flow>> finishedFlows;
static std::vector<Flow> flows;
static unsigned long timeout_interval = 60; // flow interval
static unsigned long time_offset = 0; // time to wait to start capturing fata
static unsigned long runtime = 0; // total time to run for specified by user
static unsigned long first_timestamp = 0; // fist timestamp in capture
static unsigned long start_time = 0; // time to start capture based on runtime, offset, etc.
static unsigned long max_runtime = 0; // maximum runtime for capture based on offset, runtime, etc.
static int user_specified_time = 0; // did the use specify a runtime

static std::map<size_t, Scanner> scanners;
static bool verbose = false;
static int hostsThreshold = 64;
static int portsThreshold = 64;
<<<<<<< Updated upstream
static bool debug = false;
=======
static bool debug = true;
>>>>>>> Stashed changes

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
// Move remainging flows to finishedFlows
//
void cleanup()
{
  for (auto &flow : flows) {
    size_t hashValue = flow.hashValue();
    finishedFlows[hashValue].push_back(flow);
  }
}

//
// Find scanners
//
void compileScanners()
{
  // compile all potential scanners
  for (auto &finishedFlow : finishedFlows) {
    for (auto &flow : finishedFlow.second) {
      if (debug)
        flow.print();
      //Scanner scanner(flow.srcAddr, flow.protocol);
      Scanner scanner;//(flow.srcAddr, flow.protocol);
      scanner.ip = flow.srcAddr;
      scanner.protocol = flow.protocol;
      auto scannerHash = scanner.hashValue();
      auto scannerItr = scanners.find(scannerHash);
      if (scannerItr != scanners.end()) {
        // Already tracking this scanner
        auto &s = scannerItr->second;
        auto hostItr = s.dstHosts.find(flow.dstAddr);
        if (hostItr == s.dstHosts.end()) {
          // new dest host to add
          s.dstHosts[flow.dstAddr].push_back(flow.dstPort);
        } else {
          auto portItr = std::find(hostItr->second.begin(), hostItr->second.end(), flow.dstPort);
          if (portItr == hostItr->second.end())
            hostItr->second.push_back(flow.dstPort);
        }
      } else {
        // New scanner - add it to our list of potentials
        scanner.dstHosts[flow.dstAddr].push_back(flow.dstPort);
        scanners[scannerHash] = scanner;
      }
      // TODO maybe do the same for the flow.dstAddr?
    }
  }
}
std::string getFormatedPorts(dstPorts_t& ports)
{
  // TODO clean up output so that consecutive ports look like 1, 3 -15, 21
  std::stringstream ss;
  std::sort(ports.begin(), ports.end());
  int start, end;
  end = start = ports[0];
  for (int i = 1; i < ports.size(); i++) {
    if (ports[i] == (ports[i-1] + 1))
      end = ports[i];
    else {
      if (start == end)
        ss << start << ",";
      else
        ss << start << "-" << end << ",";
      start = end = ports[i];
    }
  }

  if (start == end)
    ss << start;
  else
    ss << start << "-" << end;

  return ss.str();
}
 
bool haveScanners()
{
  for (auto &scannerItr : scanners) {
    auto &s = scannerItr.second;
    auto numHosts = s.dstHosts.size();
    if (numHosts >= hostsThreshold)
      return true;
    for (auto &hostItr : s.dstHosts) {
      auto numPorts = hostItr.second.size();
      if (numPorts >= portsThreshold)
        return true;
    }
  }

  return false;
}

bool isScanner(Scanner &s)
{
  if (s.dstHosts.size() >= hostsThreshold)
    return true;
  for (auto &hostItr : s.dstHosts) {
    if (hostItr.second.size() >= portsThreshold)
      return true;
  }
  return false;
}

void printScanners()
{
  if (!haveScanners()) {
    std::cout << "Hooray! No scanners found." << std::endl;
    return;
  }

  // will the real scanners please stand up, please stand up
  if (verbose) {
    // print scanner details
    std::cout << padString("Scanner", 16)
    << padString("Proto", 6)
    << padString("HostScanned", 16)
    << "PortsScanned" << std::endl;

    for (auto &scannerItr : scanners) {
      auto &s = scannerItr.second;
      if (isScanner(s)) {
        for (auto &hostItr : s.dstHosts) {
          auto hostName = hostItr.first;
          std::cout << padString(s.ip, 16)
          << padString(s.protocol, 6)
          << padString(hostName, 16)
          << getFormatedPorts(hostItr.second);
          std::cout << std::endl;
        }
      }
    }
  }
  std::cout << std::endl;

  std::map<std::string, std::pair<std::set<std::string>, int>> summaryScanners;
  for (auto &scannerItr : scanners) {
    auto &s = scannerItr.second;
    if (isScanner(s)) {
      if (summaryScanners.find(s.ip) == summaryScanners.end()) {
        // start counting hosts and ports for this scanner ip
        summaryScanners[s.ip] = std::make_pair(std::set<std::string>(), 0);
      }
      for (auto &hostItr : s.dstHosts) {
        summaryScanners[s.ip].first.insert(hostItr.first);
        summaryScanners[s.ip].second += hostItr.second.size();
      }
    }
  }
  
  // print scanner summary
  std::cout << "Summary:" << std::endl;
  std::cout << padString("Scanner", 16) << "#HostsScanned #PortsScanned" << std::endl;
  for (auto &scannerItr : summaryScanners) {
    std::cout << padString(scannerItr.first, 16)
    << padString(std::to_string(scannerItr.second.first.size()), 14)
    << scannerItr.second.second << std::endl;
  }
}

//
// Print usage
//
void usage()
{
  std::cout << "Usage: ./fdscan [-r filename] [-i interface] [-t time] [-o time_offset] [-S secs] [-h HNum] [-p PNum] [-V]" << std::endl;
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
  }

  // Check we're doing ok on time
  u_long curr_time = (u_long)pkthdr->ts.tv_sec;
  if (curr_time < start_time) {
    return;
  }
  if (user_specified_time == 1 && (curr_time > max_runtime)) {
    cleanup();
    compileScanners();
    printScanners();
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
    ///*DEBUG*/fprintf(stdout, "current flow time = %lu\n", flow_time);
    if (flow_time >= timeout_interval) {
      ///*DEBUG*/fprintf(stdout, "end flow\n");
      size_t hashValue = f.hashValue();
      finishedFlows[hashValue].push_back(f);
      flows.erase(flowItr);
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
        else if (f.dir == "->")
          f.dir = "<->";
        else if (f.dir == "")
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
        if (f.isOppositeDirection(flow))
          f.dir = "<->";
      }
    }

    //
    // update the state
    //
    if (f.protocol == "ICMP") {
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      //f.state = std::to_string(icmp->icmp_type);
      std::stringstream ss;
      ss << (int)icmp->icmp_type;
      f.state = ss.str();
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
      if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
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
      std::stringstream ss;
      ss << (int)icmp->icmp_type;
      flow.state = ss.str();
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

  //$ ./fdscan [-r filename] [-i interface] [-t time] [-o time_offset] [-S secs] [-h HNum] [-p PNum] [-V]
  if (argc == 1) {
    usage();
  }
  for (int i = 1; i < argc; ++i) {
    //if (strcmp(argv[i], "-h") == 0) {
    //  usage();
    if (strcmp(argv[i], "-r") == 0) {
      filename = argv[++i];
    } else if (strcmp(argv[i], "-i") == 0) {
      interface = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0) {
      user_specified_time = 1;
      runtime = std::stol(argv[++i]);
    } else if (strcmp(argv[i], "-o") == 0) {
      time_offset = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-S") == 0) {
      timeout_interval = std::stol(argv[++i]);
    } else if (strcmp(argv[i], "-h") == 0) {
      hostsThreshold = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-p") == 0) {
      portsThreshold = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-V") == 0) {
      verbose = true;
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
    pcap_t *pcap = pcap_open_live(interface.c_str(), SNAP_LEN, /*promiscuous mode*/1, 1000, errbuf);

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
  }

  // print the results
  cleanup();
  compileScanners();
  printScanners();

  return 0;
}
