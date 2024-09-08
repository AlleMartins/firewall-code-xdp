from bcc import BPF
import socket
import struct

# Carica il codice eBPF
bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>

#define THRESHOLD 10

struct ip_key_t {
    u32 src_ip;
};

BPF_HASH(counts, struct ip_key_t, u32);
BPF_PERF_OUTPUT(events);
BPF_HASH(blocked_ips, u32, u32);  // Memorizza gli IP bloccati

struct event_t {
    u32 src_ip;
    char message[256];
};

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
   
}
"""

b = BPF(text=bpf_text)

# Funzione per convertire un indirizzo IP da formato intero a stringa
def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# Callback per gestire gli eventi e stampare a terminale
def print_event(cpu, data, size):
    event = b["events"].event(data)
    src_ip = inet_ntoa(event.src_ip)
    count = b["counts"][event.src_ip].value
    print(f"IP {src_ip} ha fatto {count} connessioni stabilite. {event.message}")

# Attacca il kprobe al punto di attacco
b.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")

# Carica il programma XDP sull'interfaccia di rete (es. "eth0")
device = "wlp5s0"
b.attach_xdp(device, b.load_func("xdp_drop", BPF.XDP))

# Stampa intestazione
print("Monitoring for possible DDOS attacks...")

# Collega la funzione di callback agli eventi
b["events"].open_perf_buffer(print_event)

# Loop infinito per continuare a leggere gli eventi
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        break

# Scollega il programma XDP prima di uscire
b.remove_xdp(device)
