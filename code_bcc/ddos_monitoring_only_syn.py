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

BPF_HASH(syn_count_map, __u32, __u64, 1024);

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Solo IPv4 supportato
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end) {
        return XDP_ABORTED;
    }

    if (ether->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end) {
        return XDP_ABORTED;
    }

    // Solo TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_ABORTED;

    // Verifica se è un pacchetto SYN
    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        __u32 dest_ip = ip->daddr;
        __u64 *syn_count;

        
        // Controlla il conteggio dei SYN inviati dall'IP sorgente
        syn_count = syn_count_map.lookup(&src_ip);
        if (syn_count) {
            (*syn_count)++;
            if (*syn_count > MAX_REQUESTS) {
                bpf_trace_printk("Blocked IP: %x\\n", src_ip);
                return XDP_DROP;
            }
        } else {
            // Se syn_count è NULL, inizializza il conteggio
            __u64 initial_count = 1;
            bpf_map_update_elem(&syn_count_map, &src_ip, &initial_count, BPF_ANY);
        }

        
        // Stampa il numero di SYN inviati, l'IP sorgente e l'IP di destinazione
        bpf_trace_printk("SYN count: %llu, Source IP: %x, Destination IP: %x\\n", *syn_count, src_ip, dest_ip);
        
    }

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)

# Carica il programma XDP sull'interfaccia di rete (es. "wlp5s0")
device = "wlp5s0"
b.attach_xdp(device, b.load_func("xdp_firewall", BPF.XDP))

# Funzione per convertire l'IP da intero a formato CIDR
def int_to_ip(ipnum):
    ipnum = socket.ntohl(ipnum)  # Inverte l'endianness
    return socket.inet_ntoa(struct.pack("!I", ipnum))

# Stampa intestazione
print("Monitoring TCP SYN packets...")

# Loop per leggere gli eventi e stampare il conteggio SYN
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        msg = msg.decode('utf-8')  # Decodifica il messaggio da bytes a stringa
        if "SYN count" in msg:
            parts = msg.split(',')
            syn_count = parts[0].split(":")[1].strip()
            src_ip = int_to_ip(int(parts[1].split(":")[1].strip(), 16))
            dest_ip = int_to_ip(int(parts[2].split(":")[1].strip(), 16))
            print(f"SYN count: {syn_count}, Source IP: {src_ip}, Destination IP: {dest_ip}")
    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        break

# Scollega il programma XDP prima di uscire
b.remove_xdp(device)
