#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 131072

struct io_request_key {
	u64 sector;
	u32 dev;
	u32 padding;
};

struct io_request_entry {
	u64 start_ts;
	u64 bytes;
};

struct io_chain_stats {
	u64 total_requests;
	u64 completed_requests;
	u64 latency_sum;
	u64 latency_max;
	u64 size_mismatch;
	u64 orphan_completes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct io_request_key);
	__type(value, struct io_request_entry);
} io_request_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct io_chain_stats);
} io_stats_map SEC(".maps");

static __always_inline void update_stats_completed(u64 latency_ns)
{
	u32 key = 0;
	struct io_chain_stats *stats;

	stats = bpf_map_lookup_elem(&io_stats_map, &key);
	if (!stats)
		return;

	stats->completed_requests++;
	stats->latency_sum += latency_ns;
	if (latency_ns > stats->latency_max)
		stats->latency_max = latency_ns;
}

static __always_inline void update_stats_total(void)
{
	u32 key = 0;
	struct io_chain_stats *stats;

	stats = bpf_map_lookup_elem(&io_stats_map, &key);
	if (!stats)
		return;

	stats->total_requests++;
}

static __always_inline void update_stats_orphan(void)
{
	u32 key = 0;
	struct io_chain_stats *stats;

	stats = bpf_map_lookup_elem(&io_stats_map, &key);
	if (!stats)
		return;

	stats->orphan_completes++;
}

static __always_inline void update_stats_size_mismatch(void)
{
	u32 key = 0;
	struct io_chain_stats *stats;

	stats = bpf_map_lookup_elem(&io_stats_map, &key);
	if (!stats)
		return;

	stats->size_mismatch++;
}

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
	struct io_request_key key = {};
	struct io_request_entry entry = {};
	u64 ts = bpf_ktime_get_ns();

	key.sector = ctx->sector;
	key.dev = ctx->dev;
	key.padding = 0;

	entry.start_ts = ts;
	entry.bytes = ctx->bytes;

	if (bpf_map_update_elem(&io_request_map, &key, &entry, COMPAT_BPF_ANY) == 0) {
		update_stats_total();
	}

	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_complete *ctx)
{
	struct io_request_key key = {};
	struct io_request_entry *entry;
	u64 ts = bpf_ktime_get_ns();
	u64 latency_ns;
	u64 bytes;

	key.sector = ctx->sector;
	key.dev = ctx->dev;
	key.padding = 0;

	entry = bpf_map_lookup_elem(&io_request_map, &key);
	if (!entry) {
		update_stats_orphan();
		return 0;
	}

	latency_ns = ts - entry->start_ts;

	bytes = (u64)ctx->nr_sector * 512;
	if (entry->bytes != bytes && entry->bytes != 0) {
		update_stats_size_mismatch();
	}

	update_stats_completed(latency_ns);

	bpf_map_delete_elem(&io_request_map, &key);

	return 0;
}
