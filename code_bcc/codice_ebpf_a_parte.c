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
    struct ip_key_t key = {};
    u32 zero = 0;
    u32 *count;

    struct inet_sock *inet = inet_sk(sk);
    key.src_ip = inet->inet_saddr;

    count = counts.lookup_or_init(&key, &zero);
    (*count)++;

    if (*count >= THRESHOLD) {
        struct event_t event = {};
        event.src_ip = key.src_ip;
        bpf_probe_read_str(&event.message, sizeof(event.message), "Possible DDOS attack detected.");
        events.perf_submit(ctx, &event, sizeof(event));

        // Aggiungi l'IP alla lista degli IP bloccati
        u32 blocked = 1;
        blocked_ips.update(&key.src_ip, &blocked);
    }

    return 0;
}

// Programma XDP per bloccare i pacchetti dagli IP sospetti
int xdp_drop(struct xdp_md *ctx) {
    u32 ip_src = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        ip_src = iph->saddr;

        u32 *blocked = blocked_ips.lookup(&ip_src);
        if (blocked) {
            return XDP_DROP;  // Blocca il pacchetto
        }
    }

    return XDP_PASS;
}
