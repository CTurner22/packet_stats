//
// Created by Phil Romig on 10/30/18.
//

#ifndef PACKETSTATS_PACKETSTATS_H
#define PACKETSTATS_PACKETSTATS_H

// System include files
#include <stdlib.h>
// #include <strings.h>
// #include <string.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_set>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

// #include "linux/if_ether.h"
// #include "linux/tcp.h"
// #include "linux/ip.h"
// #include "linux/udp.h"

#include <pcap/pcap.h>

#include <iostream>     // std::cout
#include <algorithm>    // std::max
#include <vector>
#include <set>

// Include files specific to this project.
#include "networkStructures.h"
#include "statisticsC.h"
#include "resultsC.h"


// Prototype for the packet processor, called once for each packet.
void pk_processor(u_char *, const struct pcap_pkthdr *, const u_char *);



// Garbage needed for the debugging functions.
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>

#define TRACE BOOST_LOG_TRIVIAL(trace) << "TRACE: "
#define DEBUG BOOST_LOG_TRIVIAL(debug)  << "DEBUG: "
#define INFO BOOST_LOG_TRIVIAL(info)   << "INFO: "
#define WARNING BOOST_LOG_TRIVIAL(warning) << "WARNING: "
#define ERROR BOOST_LOG_TRIVIAL(error)  << "ERROR: "
#define FATAL BOOST_LOG_TRIVIAL(fatal)  << "FATAL: "
#define ENDL  " (" << __FILE__ << ":" << __LINE__ << ")"

#endif //PACKETSTATS_PACKETSTATS_H
