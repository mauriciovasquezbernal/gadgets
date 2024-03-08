#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/macros.h>
#include <bpf/bpf_core_read.h>

struct event {
	__u64 mntns_id;
	__u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// [Optional] Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event event = {};
	struct task_struct *task;

	event.pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	event.mntns_id = (u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";