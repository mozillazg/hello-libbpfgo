#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14                                        /* Total octets in header.	 */
#define MAX_TCP_PAYLOAD_SIZE 256

SEC("socket")
int socket__filter_demo(struct __sk_buff *skb) {
    u16 h_proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto)) < 0) {
        return 0;
    }
    if (bpf_ntohs(h_proto) != ETH_P_IP) { // not ipv4
        return 0;
    }

    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_hdr, sizeof(ip_hdr)) < 0) {
        return 0;
    }
    if (ip_hdr.protocol != IPPROTO_TCP) { // not tcp
        return 0;
    }

    struct tcphdr tcp_hdr;
    u8 ip_ihl = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_ihl, sizeof(ip_ihl)) < 0) {
        return 0;
    }
    u32 ip_hdr_len = (ip_ihl & 0x0f) * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return 0;
    }
    if (bpf_skb_load_bytes(skb, ETH_HLEN + ip_hdr_len, &tcp_hdr, sizeof(tcp_hdr)) < 0) {
        return 0;
    }

    if (tcp_hdr.dest != bpf_htons(9090)) { // not 9090 port
        return 0;
    }

    u16 tcp_doff;
    u32 tcp_hdr_offset = ETH_HLEN + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_hdr_offset + 12, &tcp_doff, sizeof(tcp_doff)) < 0) {
        return 0;
    }
    u32 tcp_hdr_len = ((tcp_doff & 0xf0) >> 4) * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) {
        return 0;
    }

    u16 total_len_be;   // Network byte order
    u16 total_len_host; // Host byte order
    int offset_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);
    if (bpf_skb_load_bytes(skb, offset_tot_len, &total_len_be, sizeof(total_len_be)) < 0) {
        return 0;
    }
    total_len_host = bpf_ntohs(total_len_be);
    if (total_len_host < ip_hdr_len + tcp_hdr_len) {
        return 0;
    }

    // read tcp payload
    char tcp_payload[MAX_TCP_PAYLOAD_SIZE];
    __builtin_memset(&tcp_payload, 0, sizeof(tcp_payload));
    u32 tcp_payload_offset = ETH_HLEN + ip_hdr_len + tcp_hdr_len;
    u32 tcp_payload_len = total_len_host - ip_hdr_len - tcp_hdr_len;
    bpf_printk("tcp_payload_len: %d", tcp_payload_len);

    if (tcp_payload_len == 0) {
        goto out;
    } else if (tcp_payload_len >= MAX_TCP_PAYLOAD_SIZE) {
        bpf_printk("tcp_payload_len > MAX_TCP_PAYLOAD_SIZE");
        if (bpf_skb_load_bytes(skb, tcp_payload_offset, &tcp_payload, MAX_TCP_PAYLOAD_SIZE) < 0) {
            goto out;
        }
    } else if (tcp_payload_len == 1) {
        bpf_printk("tcp_payload_len == 1");
        if (bpf_skb_load_bytes(skb, tcp_payload_offset, &tcp_payload, 1) < 0) {
            goto out;
        }
    } else {
        // avoid
        //    call bpf_skb_load_bytes#26
        //    R4 invalid zero-sized read: xxx
        // or
        //    call bpf_skb_load_bytes#26
        //    R4 min value is negative, either use unsigned or 'var &= const'
        u32 read_size = sizeof(tcp_payload) - 1;
        if (read_size > tcp_payload_len - 1) {
            read_size = tcp_payload_len - 1;
        }
        bpf_printk("read_size: %d", read_size);
        if (read_size == 0) {
            goto out;
        }

        if (bpf_skb_load_bytes(skb, tcp_payload_offset, &tcp_payload, read_size + 1) < 0) {
            goto out;
        }
        bpf_printk("read size: %d", read_size + 1);
    }

    bpf_printk("saddr: %pI4, daddr: %pI4:%d, payload: %s", &ip_hdr.saddr, &ip_hdr.daddr,
               bpf_htons(tcp_hdr.dest), tcp_payload);

out:
    return 0;
}

char _license[] SEC("license") = "GPL";
