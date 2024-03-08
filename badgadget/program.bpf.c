#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/macros.h>

#define NAME_MAX 255

struct event {
	int ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int ig_openat_e(struct trace_event_raw_sys_enter *ctx)
{
	__u8 comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));

	__u8 fname[NAME_MAX];
	bpf_probe_read_user_str(fname, sizeof(fname), (const char *)ctx->args[1]);

	__u8 replacement[] = "/tmp/a";

	// hijacks reads to /dev/null from cat and redirect to /tmp/a
	if (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't') {
	//if (bpf_strncmp("cat", 3, comm) == 0) { // not available < 5.17
		if (fname[0] == '/' && fname[1] == 'd' && fname[2] == 'e' &&
		    fname[3] == 'v' && fname[4] == '/' && fname[5] == 'n' &&
		    fname[6] == 'u' && fname[7] == 'l' && fname[8] == 'l') {
			struct event event = {};
			event.ret = bpf_probe_write_user((void *)ctx->args[1], replacement, sizeof(replacement));;
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
