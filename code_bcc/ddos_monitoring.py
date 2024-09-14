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

__attribute__((section("xdp"), used))
int xdp_firewall(struct xdp_md *ctx);

BPF_HASH(ip_count_map, __u32, __u64);

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

    // Solo TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Header TCP
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_ABORTED;

    // Controlla se è un pacchetto ACK senza SYN (connessione stabilita)
    if (tcp->ack && !tcp->syn) {
        
        // Verifica il SYN cookie
        if (!bpf_tcp_raw_check_syncookie_ipv4(ip, tcp)) {
            // Cookie non valido, scarta il pacchetto
            bpf_trace_printk("Blocked IP: %x\\n", ip->saddr);
            return XDP_DROP;
        }

        // Cookie valido, consenti il passaggio al kernel
        return XDP_PASS;
    }
        
    // Verifica se è un pacchetto SYN
    if (tcp->syn && !tcp->ack) {
        __u32 cookie_seq = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, sizeof(*tcp));

        if (cookie_seq == 0)
            return XDP_PASS;

        tcp->ack = 1; 
        tcp->ack_seq = htonl(ntohl(tcp->seq) + 1); 
        tcp->seq = cookie_seq;

        __u32 old_saddr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = old_saddr;

        __u16 old_sport = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = old_sport;

        // Ricalcola i checksum IP e TCP
        tcp->check = 0;
        ip->check = 0;
        // Se ci sono helper specifici per checksum TCP, usa quelli
        tcp->check = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
        ip->check = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);

        return XDP_TX;
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
            ip_hex = msg.split("Blocked IP: ")[1].strip()
            ip_num = int(ip_hex, 16)
            print(f"Blocked IP: {int_to_ip(ip_num)}")
    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        break

# Scollega il programma XDP prima di uscire
b.remove_xdp(device)
