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

BPF_HASH(ip_blocked_map, __u32, __u64);  // Mappa per IP bloccati
BPF_HASH(ip_syn_count, __u32, __u64);    // Mappa per conteggio dei pacchetti SYN

#define MAX_SYN_COUNT 5  // Soglia massima per SYN

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Solo IPv4 supportato per questo esempio
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

    // Controlla se l'IP è già bloccato
    __u64 *blocked = ip_blocked_map.lookup(&ip->saddr);
    if (blocked) {
        bpf_trace_printk("Already blocked IP: %x\\n", ip->saddr);
        return XDP_DROP;
    }

    // Controlla se è un pacchetto ACK senza SYN (connessione stabilita)
    if (tcp->ack && !tcp->syn) {
        if (!bpf_tcp_raw_check_syncookie_ipv4(ip, tcp)) {
            __u64 val = 1;
            ip_blocked_map.update(&ip->saddr, &val);
            bpf_trace_printk("Blocked IP: %x\\n", ip->saddr);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    // Verifica se è un pacchetto SYN
    if (tcp->syn && !tcp->ack) {
        __u64 *syn_count = ip_syn_count.lookup(&ip->saddr);
        if (syn_count) {
            *syn_count += 1;
            ip_syn_count.update(&ip->saddr, syn_count);

            // if (*syn_count > MAX_SYN_COUNT) {
            //    __u64 val = 1;
            //    ip_blocked_map.update(&ip->saddr, &val);
            //    // bpf_trace_printk("Blocked IP: %x\\n", ip->saddr);
            //    return XDP_DROP;
            // }
        } else {
            __u64 initial_count = 1;
            ip_syn_count.update(&ip->saddr, &initial_count);
        }

        // Genera SYN cookie
        __u32 cookie_seq = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, sizeof(*tcp));
        if (cookie_seq == 0)
            return XDP_PASS;

        bpf_trace_printk("Generated SYN cookie for IP: %x\\n", ip->saddr);

        tcp->ack = 1; 
        tcp->ack_seq = htonl(ntohl(tcp->seq) + 1); 
        tcp->seq = cookie_seq;

        __u32 old_saddr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = old_saddr;

        __u16 old_sport = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = old_sport;

        tcp->check = 0;
        ip->check = 0;
        tcp->check = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), 0);
        ip->check = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);

        return XDP_TX;
    }

    return XDP_PASS;
}
"""

b = BPF(text=bpf_text)

device = "wlp5s0"
b.attach_xdp(device, b.load_func("xdp_firewall", BPF.XDP))

def int_to_ip(ipnum):
    ipnum = socket.ntohl(ipnum)
    return socket.inet_ntoa(struct.pack("!I", ipnum))

syn_cookie_printed = set()
already_blocked_printed = set()

print("Monitoring for possible DDOS attacks...")

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        msg = msg.decode('utf-8')

        if "Blocked IP" in msg:
            ip_hex = msg.split("Blocked IP: ")[1].strip()
            ip_num = int(ip_hex, 16)
            print(f"Blocked IP: {int_to_ip(ip_num)}")

        if "Generated SYN cookie for IP" in msg:
            ip_hex = msg.split("Generated SYN cookie for IP: ")[1].strip()
            ip_num = int(ip_hex, 16)
            if ip_num not in syn_cookie_printed:
                print(f"Generated SYN cookie for IP: {int_to_ip(ip_num)}")
                syn_cookie_printed.add(ip_num)

        if "Already blocked IP" in msg:
            ip_hex = msg.split("Already blocked IP: ")[1].strip()
            ip_num = int(ip_hex, 16)
            if ip_num not in already_blocked_printed:
                print(f"Already blocked IP: {int_to_ip(ip_num)}")
                already_blocked_printed.add(ip_num)

    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        break

b.remove_xdp(device)
