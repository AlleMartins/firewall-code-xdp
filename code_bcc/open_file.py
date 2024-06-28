from bcc import BPF
import requests
import json

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

int trace_do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how) {
    struct data_t data = {};
    
    if (!filename)
        return 0;

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    if (strcmp(data.filename, "/var/log/auth.log") != 0)  // Update the path
        return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="do_sys_openat2", fn_name="trace_do_sys_openat2")

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
    
    # Print event to terminal
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, event.filename))
    
    # Create JSON data
    event_data = {
        "time_s": time_s,
        "comm": event.comm.decode('utf-8', 'replace'),
        "pid": event.pid,
        "filename": event.filename.decode('utf-8', 'replace')
    }
    
    # Send JSON data to server
    try:
        response = requests.post('http://127.0.0.1:5000/json', json=event_data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to send data: {e}")

# Loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
