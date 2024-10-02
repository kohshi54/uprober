from bcc import BPF
from bcc.utils import printb

def print_event(cpu, data, size):
	#event = ct.cast(data, ct.POINTER(Data)).contents
	event = b["events"].event(data)
	#print(f"{event.buf}")
	printb(b"%s" % event.buf)

b = BPF(src_file="trace.bpf.c")
b.attach_uprobe(name="./a.out", sym="change_buf", fn_name="read_buf")
b.attach_uretprobe(name="./a.out", sym="change_buf", fn_name="read_altered_buf")
b["events"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
		#b.trace_print()
	except KeyboardInterrupt:
		break

