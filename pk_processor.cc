//
// Created by Phil Romig on 11/13/18.
//

#include "packetstats.h"

// ****************************************************************************
// * pk_processor()
// *  Most/all of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    resultsC* results = (resultsC*)user;
    results->incrementTotalPacketCount();
    DEBUG << "Processing packet #" << results->packetCount() << ENDL;
    char s[256]; memset(s,0,256); memcpy(s,ctime(&(pkthdr->ts.tv_sec)),strlen(ctime(&(pkthdr->ts.tv_sec)))-1);
    TRACE << "\tPacket timestamp is " << s;
    TRACE << "\tPacket capture length is " << pkthdr->caplen ;
    TRACE << "\tPacket physical length is " << pkthdr->len ;

    // ***********************************************************************
    // * Process the link layer header
    // *  Hint -> use the ether_header structure defined in
    // ***********************************************************************
	auto eth_hdr = reinterpret_cast<const struct ethhdr*>(packet);


	// *******************************************************************
	// * If it's an ethernet packet, extract the src/dst address and  
	// * find the ethertype value to see what the next layer is.
	// * 
	// * If it's not an ethernet packet, count is as "other" and your done
	// * with this packet.
	// *******************************************************************
	if (eth_hdr->h_proto > 1536) {
		results->newEthernet(pkthdr->len);
		results->newSrcMac(std::vector<unsigned char>(eth_hdr->h_source, eth_hdr->h_source + ETH_ALEN));
		results->newDstMac(std::vector<unsigned char>(eth_hdr->h_dest, eth_hdr->h_dest + ETH_ALEN));

	} else {
		// IEEE 802.3
		results->newOtherLink(pkthdr->len);
		return;
	}		

    // ***********************************************************************
    // * Process the network layer
    // ***********************************************************************

	// *******************************************************************
	// *  Use ether_type to decide what the next layer is.  You
	// *  If it's ARP or IPv6 count it and you are done with this packet.
	// * 
	// * If it's IPv4 extract the src and dst addresses and find the
	// * protocol field to see what the next layer is.  
	// * 
	// * If it's not ARP, IPv4 or IPv6 count it as otherNetwork.
	// *******************************************************************

	switch (eth_hdr->h_proto) {
		case ETH_P_ARP:
			results->newARP(pkthdr->len);
			return;

		case ETH_P_IPV6:
			results->newIPv6(pkthdr->len);
			return;
		
		case ETH_P_IP:
			results->newIPv4(pkthdr->len);
			break;

		default:
			results->newOtherNetwork(pkthdr->len);
			return;
		
	}

	auto ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ethhdr));
	results->newSrcIPv4(ip_hdr->ip_src.s_addr);
	results->newDstIPv4(ip_hdr->ip_dst.s_addr);



    // ***********************************************************************
    // * Process the transport layer header
    // ***********************************************************************

    	// *******************************************************************
	// * If the packet is an IPv4 packet, then use the Protcol field
	// * to find out what the next layer is.
	// * 
	// * If it's ICMP, count it and you are done with this packet.
	// *
	// * If it's UDP or TCP, decode the transport hearder to extract
	// * the src/dst ports and TCP flags if needed.
	// *
	// * If it's not ICMP, UDP or TCP, count it as otherTransport
    	// *******************************************************************

	switch (ip_hdr->ip_p) {
		case IPPROTO_ICMP: {
			results->newICMP(pkthdr->len);
			return;
		}
		case IPPROTO_UDP: {
			auto udp_hdr = reinterpret_cast<const struct udphdr*>(packet + sizeof(ethhdr) + sizeof(ip));
			results->newSrcUDP(udp_hdr->source);
			results->newDstUDP(udp_hdr->dest);
			results->newUDP(pkthdr->len);
			return;
		}
		case IPPROTO_TCP: {
			auto tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + sizeof(ethhdr) + sizeof(ip));
			results->newSrcTCP(tcp_hdr->source);
			results->newDstTCP(tcp_hdr->dest);
			results->newTCP(pkthdr->len);

			if (tcp_hdr->fin)
				results->incrementFinCount();

			if (tcp_hdr->syn)
				results->incrementSynCount();

			return;
		}
		default:
			results->newOtherTransport(pkthdr->len);
	}





    return;
}
