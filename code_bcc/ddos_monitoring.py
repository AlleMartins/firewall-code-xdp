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

    // Solo TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Header TCP
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_ABORTED;

    // Controlla se la connessione è già stabilita (ACK set senza SYN)
    if (tcp->ack && !tcp->syn) {
        // Valida il cookie se necessario
        if (!bpf_tcp_check_syncookie(ctx, (void *)(long)ip->saddr, ip->daddr, (void *)(long)tcp->source, tcp->dest)) {
            // Cookie non valido, scarta il pacchetto
            return XDP_DROP;
        }
        // Cookie valido, passa al kernel
        return XDP_PASS;
    }
        
    // Verifica se è un pacchetto SYN
    if (tcp->syn && !tcp->ack) {
        // Genera il SYN cookie
        __u32 seq = bpf_tcp_gen_syncookie(ctx, (void *)(long)ip->saddr, ip->daddr, (void *)(long)tcp->source, tcp->dest);

        // Se il SYN cookie non è stato generato, passiamo il pacchetto al kernel
        if (seq == 0)
            return XDP_PASS;

        // Modifica il pacchetto in SYN-ACK
        tcp->ack = 1; // Imposta il flag ACK
        tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1); // Acknowledge il pacchetto SYN

        // Imposta il numero di sequenza con il SYN cookie generato
        tcp->seq = seq;

        // Aggiorna l'header IP (swap di indirizzi IP)
        __u32 old_saddr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = old_saddr;

        // Aggiorna l'header TCP (swap delle porte TCP)
        __u16 old_sport = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = old_sport;

        // Ricalcola i checksum IP e TCP
        tcp->check = 0;
        tcp->check = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
        ip->check = 0;
        ip->check = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);

        // Invia il pacchetto come risposta SYN-ACK tramite XDP_TX
        return XDP_TX;
    }

    // Se non ci sono SYN o ACK, scarta il pacchetto
    return XDP_DROP;
    
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
