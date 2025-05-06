#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */
#define MAX_TCP_PAYLOAD_SIZE 256
#define MIN_HTTP_PREFIX_LEN 15
#define MAX_HEADER_LEN 128

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2

#define MAX_VALUE_SIZE 64

struct result_t {
    char value[MAX_VALUE_SIZE];
};

// extract "User-Agent"
// don't trust the result if the request is coming from user
static __always_inline int extract_user_agent_header(
    struct __sk_buff *skb, u32 offset, int msg_len, struct result_t *result) {
    int i, start_pos = -1;
    long err;
    u32 initial_offset = offset; // Store initial offset for later use

    // Limit search length to prevent excessive processing
    int search_len = msg_len;
    if (search_len > MAX_HEADER_LEN) {
        search_len = MAX_HEADER_LEN;
    }

    // Search for "User-Agent: " header (12 characters)
    char word[] = "User-Agent: ";
    #pragma unroll
    for (i = 0; i <= search_len - 12; i++) {
        err = bpf_skb_load_bytes(skb, offset, &word, sizeof(word)-1);
         if (err < 0) {
             bpf_printk("BPF read word failed at offset %d, err %d", offset, err);
             break;
         }
         bpf_printk("offset %d, word: %s", offset, word);
         // Check for exact match with "User-Agent: "
         if (word[0] == 'U' && word[1] == 's' && word[2] == 'e' &&
             word[3] == 'r' && word[4] == '-' && word[5] == 'A' &&
             word[6] == 'g' && word[7] == 'e' && word[8] == 'n' &&
             word[9] == 't' && word[10] == ':' && word[11] == ' ') {
            start_pos = i + 12; // Skip "User-Agent: "
            break;
        }
        offset++;
    }

    // If "User-Agent: " not found, return error
    if (start_pos < 0) {
        bpf_printk("'User-Agent: ' not found");
        return -1;
    }

    // Check if there's enough data to read User-Agent value
    if (search_len - start_pos <= 0) {
        bpf_printk("invalid data");
        return -1;
    }
    offset = initial_offset + start_pos;

    // Read the User-Agent value until CR, LF or buffer full
    int j = 0;
    #pragma unroll
    for (j = 0; j <= MAX_VALUE_SIZE - 1 && j <= search_len - start_pos; j++) {
        char c;
        err = bpf_skb_load_bytes(skb, offset + j, &c, sizeof(c));
        if (err < 0) {
            bpf_printk("BPF read failed at offset %d, err %d", offset + j, err);
            break;
        }

        // Stop at line break
        if (c == '\r' || c == '\n') {
            break;
        }

        result->value[j] = c;
    }
    result->value[j] = '\0'; // Null-terminate the string

    return 0;
}


SEC("tc")
int handle_egress(struct __sk_buff *skb) {
    bpf_skb_pull_data(skb, 0);

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        goto out;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) { // not tcp
        goto out;
    }

    u8 ip_ihl = 0;
    bpf_probe_read_kernel(&ip_ihl, sizeof(u8), (void *)ip_hdr);
    u32 ip_hdr_len = (ip_ihl & 0x0f) * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        goto out;
    }
    if ((void *)ip_hdr + ip_hdr_len > data_end) {
        goto out;
    }

    struct tcphdr *tcp_hdr = (void *)ip_hdr + ip_hdr_len;
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        goto out;
    }
    if (tcp_hdr->dest != bpf_htons(9090)) { // not 9090 port
        goto out;
    }

    u16 tcp_doff = 0;
    bpf_probe_read_kernel(&tcp_doff, sizeof(u16), (void *)tcp_hdr + 12);
    u32 tcp_hdr_len = ((tcp_doff & 0xf0) >> 4) * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) {
        goto out;
    }
    u32 total_len_host = bpf_ntohs(ip_hdr->tot_len);
    if (total_len_host < ip_hdr_len + tcp_hdr_len) {
        goto out;
    }
    if ((void *)tcp_hdr + tcp_hdr_len > data_end) {
        goto out;
    }

    u32 tcp_payload_len = total_len_host - ip_hdr_len - tcp_hdr_len;
    if (tcp_payload_len < MIN_HTTP_PREFIX_LEN) {
        goto out;
    }

    // GET / HTTP/1.1
    char http_req_prefix[MIN_HTTP_PREFIX_LEN] = {0};
    u32 tcp_payload_offset = ETH_HLEN + ip_hdr_len + tcp_hdr_len;
    if (tcp_payload_offset + tcp_payload_len > skb->len) {
        goto out;
    }
    if (bpf_skb_load_bytes(skb, tcp_payload_offset, &http_req_prefix, sizeof(http_req_prefix)) < 0) {
        goto out;
    }

    if (http_req_prefix[0] == 'G' &&
        http_req_prefix[1] == 'E' &&
        http_req_prefix[2] == 'T' &&
        http_req_prefix[3] == ' ' &&
        http_req_prefix[4] == '/') { // `GET /`
        bpf_printk("HTTP GET request detected");
    } else {
        goto out;
    }

    struct result_t result = {0};
    __builtin_memset(&result.value, 0, sizeof(result.value));
    if (extract_user_agent_header(skb, tcp_payload_offset+15, tcp_payload_len-15, &result) == 0) {
        bpf_printk("User-Agent: %s", result.value);
    } else {
        bpf_printk("User-Agent not found");
    }

    bpf_printk("final User-Agent: %s", result.value);

out:
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
