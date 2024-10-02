#include <uapi/linux/ptrace.h>

struct data_t {
	char buf[12];
};

BPF_HASH(buf_addr, u32, u64); //local var no addr hozon
BPF_PERF_OUTPUT(events);

int read_buf(struct pt_regs *ctx, const void *buf) {
	//if (!PT_REGS_PARM2(ctx))
	//	return 0;
	if (!PT_REGS_PARM1(ctx)) // first input parameter
		return 0;
	
	struct data_t data = {};
	//bpf_probe_read_user();
	//bpf_probe_read(&data.buf, sizeof(data.buf), (void *)PT_REGS_PARM2(ctx));
	bpf_probe_read(&data.buf, sizeof(data.buf), buf);
	//bpf_trace_printk("%s", data.buf);
	events.perf_submit(ctx, &data, sizeof(data));

	u32 pid = bpf_get_current_pid_tgid();
	u64 param_addr = PT_REGS_PARM1(ctx);
	buf_addr.update(&pid, &param_addr);

	return 0;
};

int read_altered_buf(struct pt_regs *ctx) {
	struct data_t data = {};

	u32 pid = bpf_get_current_pid_tgid();
	u64 *param_addr = buf_addr.lookup(&pid);
	if (param_addr == 0)
		return 0;

	bpf_probe_read_user(&data.buf, sizeof(data.buf), (void *)*param_addr);
	events.perf_submit(ctx, &data, sizeof(data));

	buf_addr.delete(&pid);
	bpf_trace_printk("%d", PT_REGS_RC(ctx)); // kaeriti
	return 0;
}

