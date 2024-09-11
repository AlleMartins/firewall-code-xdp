from bcc import BPF
import socket
import struct
import ctypes as ct

# Carica il codice eBPF
bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_REQUESTS 15

__attribute__((section("xdp"), used))
int xdp_firewall(struct xdp_md *ctx);

BPF_HASH(ip_count_map, __u32, __u64, 1024);

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Only IPv4 supported for this example
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end) {
        // Malformed Ethernet header
        return XDP_ABORTED;
    }

    if (ether->h_proto != htons(ETH_P_IP)) {
        // Non IPv4 traffic
        return XDP_PASS;
    }

    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
        // Malformed IPv4 header
        return XDP_ABORTED;
    } 

    __u32 src_ip = ip->saddr;
    __u64 *req_count;

    // Lookup the current request count for this IP
    req_count = ip_count_map.lookup(&src_ip);
    if (req_count) {
        // Increment the request count
        (*req_count)++;
        if (*req_count > MAX_REQUESTS) {
            
            bpf_trace_printk("Blocked IP: %x\\n", src_ip);

            // Drop the packet if request limit is exceeded
            return XDP_DROP;
        }
    } else {
        // Initialize the request count to 1
        __u64 initial_count = 1;
        ip_count_map.update(&src_ip, &initial_count);
    }

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)

# Carica il programma XDP sull'interfaccia di rete (es. "eth0")
device = "wlp5s0"
b.attach_xdp(device, b.load_func("xdp_firewall", BPF.XDP))

# Funzione per convertire l'IP da intero a formato CIDR
def int_to_ip(ipnum):
    ipnum = socket.ntohl(ipnum)  # Inverte l'endianness
    return socket.inet_ntoa(struct.pack("!I", ipnum))

# Stampa intestazione
print("Monitoring for possible DDOS attacks...")

# Loop infinito per continuare a leggere gli eventi
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        msg = msg.decode('utf-8')  # Decodifica il messaggio da bytes a stringa
        if "Blocked IP" in msg:
            ip_num = int(msg.split("Blocked IP: ")[1], 16)
            print(f"Blocked IP: {int_to_ip(ip_num)}")
    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        break

# Scollega il programma XDP prima di uscire
b.remove_xdp(device)
