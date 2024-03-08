How to compile ig binary locally to test TC support

These instructions concentrate only on building ig, kubernetes is out of scope.

# Compiling ig

1. Clone repository and checkout branch from PR
```
$ git clone https://github.com/inspektor-gadget/inspektor-gadget.git -b mauricio/experiments/support-tc
```
2. Follow https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/devel/CONTRIBUTING.md#getting-started to install dependencies

3. Build ig binary
```
$ make ig
# also go build ./cmd/ig/ in the root directory of IG should work
```

4. Install ig
```
$ sudo make install/ig
```

# Build your gadget

Take the gadget shown as example in https://github.com/inspektor-gadget/inspektor-gadget/pull/2376:

```c
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

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

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		bpf_printk("comm: %s, pid: %d", skb_val->task, skb_val->pid_tgid >> 32);
	}

	return TC_ACT_UNSPEC;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb) {
	//bpf_printk("Packet on ingress");

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

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (skb_val != NULL) {
		bpf_printk("comm: %s, pid: %d", skb_val->task, skb_val->pid_tgid >> 32);
	}

	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";

```

```bash
# create a folder for it
$ mkdir mygadget
$ cd mygadget

# save above code in program.bpf.c
$ vim program.bpf.c

# enable experimental mode
$ export IG_EXPERIMENTAL=true
# build gadget (it can take a bit of time the first time because a largec container image has to be pulled)
$ sudo -E ig image build . -t mygadgettc
```

### Running the gadget

```bash
$ sudo -E ig run mygadget
```

Check the messages printed to `/sys/kernel/debug/tracing/trace_pipe`

By default the gadget attaches to all containers running on the system, it can be changed:

```bash
# attach only to mycontainer
$ sudo -E ig run mygadget -c mycontainer

# attach to a specific interface on the host
$ sudo -E ig run mytcgadget --iface enp5s0
```
