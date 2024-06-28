from bcc import BPF

# Define BPF program
prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    struct data_t data = {};
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;

    if (d_name.len >= sizeof(data.filename)) {
        return 0;
    }

    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name.name);

    if (strcmp(data.filename, "/home/ubuntu/Scrivania/prova_file.txt") != 0) {  // Update the path
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_vfs_writev(struct pt_regs *ctx, struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos) {
    struct data_t data = {};
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;

    if (d_name.len >= sizeof(data.filename)) {
        return 0;
    }

    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name.name);

    if (strcmp(data.filename, "/home/ubuntu/Scrivania/prova_file.txt") != 0) {  // Update the path
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
b.attach_kprobe(event="vfs_writev", fn_name="trace_vfs_writev")

# Header
print("%-18s %-16s %-6s %-s" % ("TIME(s)", "COMM", "PID", "FILENAME"))

# Process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, event.filename))

# Loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
