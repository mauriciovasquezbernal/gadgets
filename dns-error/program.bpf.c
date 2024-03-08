#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <linux/udp.h> // Include header file with UDP definition

#define DNS_QUERY 0
#define DNS_RESPONSE 1

#define RCODE_REFUSED  5

#define RCODE_NXDOMAIN 3

/* Refer DNS header : https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

                                   1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
	// taken from https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
	// TODO: does it have to be changed according to endianess of the host?
	struct {
//		unsigned char rd :1; // recursion desired
//		unsigned char tc :1; // truncated message
//		unsigned char aa :1; // authoritive answer
//		unsigned char opcode :4; // purpose of message
//		unsigned char qr :1; // query/response flag
//
//		unsigned char rcode :4; // response code
//		unsigned char cd :1; // checking disabled
//		unsigned char ad :1; // authenticated data
//		unsigned char z :1; // its z! reserved
//		unsigned char ra :1; // recursion available
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
# elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	};
	__u16 flags;
};


/*
The DNS header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
struct dnshdr {
	__u16 id;

	union dnsflags flags;

	__u16 qdcount; // number of question entries
	__u16 ancount; // number of answer entries
	__u16 nscount; // number of authority records
	__u16 arcount; // number of additional records
};


char __license[] SEC("license") = "GPL";

SEC("classifier/ingress/dns-error")
int ingress_drop(struct __sk_buff *skb) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_UNSPEC;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_UNSPEC;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_UNSPEC;

	bpf_printk("ingress: src:%pi4 -> dst: %pi4", &ip->saddr, &ip->daddr);

	// Check if the packet is udp
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
		return TC_ACT_UNSPEC;

	bpf_printk("ingress: src:%u -> dst: %u", bpf_ntohs(udp->source), bpf_ntohs(udp->dest));

	// check dns port
	if (udp->source != bpf_htons(53) /*&& udp->dest != 53*/) {
		bpf_printk("no dns packet, returning");
		return TC_ACT_UNSPEC;
	}

	struct dnshdr *dns = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) > data_end)
		return TC_ACT_UNSPEC;

	bpf_printk("ingress: faking dns error");
	bpf_printk("original rcode is %u", dns->flags.rcode);

	dns->flags.rcode = RCODE_NXDOMAIN;

	return TC_ACT_UNSPEC;
}