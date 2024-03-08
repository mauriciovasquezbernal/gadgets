#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>

struct event {
	__u32 pid;
	__u32 uid;
	__u64 mountnsid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// [Optional] Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();

 	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";