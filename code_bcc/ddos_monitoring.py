from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import socket
import struct
import ctypes

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
    u8 conn_type;
    u32 src_ip;
    u32 dst_ip;
    u16 dport;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();

    // stash the sock ptr for lookup on return
    currsock.update(&pid, &sk);

    return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;    // missed entry
    }

    if (ret != 0) {
        // failed to send SYN packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;

    // create and output event
    struct event evt = {
        .conn_type = 1, // 1 indicates SYN
        .src_ip = saddr,
        .dst_ip = daddr,
        .dport = ntohs(dport)
    };
    events.perf_submit(ctx, &evt, sizeof(evt));

    currsock.delete(&pid);

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# define event structure in Python
class Event(ctypes.Structure):
    _fields_ = [
        ("conn_type", ctypes.c_ubyte),
        ("src_ip", ctypes.c_uint),
        ("dst_ip", ctypes.c_uint),
        ("dport", ctypes.c_ushort)
    ]

# header
print("%-6s %-12s %-16s %-16s %-6s" % ("PID", "COMM", "SADDR", "DADDR", "DPORT"))

# function to convert IP addresses from integer to dotted string format
def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# function to print events
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    printb(b"%-6d %-12s %-16s %-16s %-6d" % (
        event.conn_type,
        int_to_ip(event.src_ip).encode(),
        int_to_ip(event.dst_ip).encode(),
        event.dport))

# open perf buffer
b["events"].open_perf_buffer(print_event)

print("Monitoring SYN packets... Press Ctrl+C to stop.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
