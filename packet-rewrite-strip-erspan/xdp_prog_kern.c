/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

SEC("xdp_erspan_remove")
int  xdp_prognum2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type;
	char *dest;

	/* Start of packet */
	nh.pos = data;

	if (nh.pos + 0x34 > data_end)
		return XDP_PASS;

	/* Check if we have eth header 0x26 into packet */
	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Moving Ethernet header, dest overlap with src, memmove handle this */
	dest = data;
	dest+= 0x26;

	/* Move start of packet header seen by Linux kernel stack */
	bpf_xdp_adjust_head(ctx, 0x26);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
