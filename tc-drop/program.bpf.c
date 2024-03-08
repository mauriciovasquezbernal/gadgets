#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

const volatile __u32 drop_addr = 134743044; // 8.8.8.8

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_UNSPEC;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	bpf_printk("egress: src:%pi4 -> dst: %pi4", &ip->saddr, &ip->daddr);

	if (ip->daddr == bpf_ntohl(drop_addr)) {
		bpf_printk("dropping in egress");
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_UNSPEC;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	bpf_printk("ingress: src:%pi4 -> dst: %pi4", &ip->saddr, &ip->daddr);

	if (ip->saddr == bpf_ntohl(drop_addr)) {
		bpf_printk("dropping in ingress");
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC;
}