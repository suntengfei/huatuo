#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct page_cache_stats {
	u64 dirty_events;
	u64 writeback_events;
	u64 pages_dirtied;
	u64 pages_written;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct page_cache_stats);
} page_stats_map SEC(".maps");

SEC("tracepoint/writeback/writeback_dirty_page")
int trace_writeback_dirty_page(struct trace_event_raw_writeback_dirty_page *ctx)
{
	u32 key = 0;
	struct page_cache_stats *stats;

	stats = bpf_map_lookup_elem(&page_stats_map, &key);
	if (stats) {
		stats->dirty_events++;
		stats->pages_dirtied++;
	}

	return 0;
}

SEC("tracepoint/writeback/writeback_pages_written")
int trace_writeback_pages_written(struct trace_event_raw_writeback_pages_written *ctx)
{
	u32 key = 0;
	struct page_cache_stats *stats;

	stats = bpf_map_lookup_elem(&page_stats_map, &key);
	if (stats) {
		stats->writeback_events++;
		stats->pages_written += ctx->pages;
	}

	return 0;
}
