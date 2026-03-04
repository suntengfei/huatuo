#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 131072
#define MAX_DIRTY_AGE_NS 30000000000ULL

struct page_key {
	u64 page_addr;
};

struct dirty_page_info {
	u64 mark_dirty_ts;
	u64 writeback_ts;
	u64 inode;
	u32 pid;
	u8 state;
	char comm[COMPAT_TASK_COMM_LEN];
};

struct page_cache_stats {
	u64 dirty_pages;
	u64 writeback_pages;
	u64 clean_pages;
	u64 invalidate_count;
	u64 dirty_age_sum;
	u64 dirty_age_max;
	u64 writeback_fail;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct page_key);
	__type(value, struct dirty_page_info);
} dirty_page_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct page_cache_stats);
} page_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

struct page_alert_event {
	u64 timestamp;
	u64 page_addr;
	u64 inode;
	u64 dirty_age_ns;
	u32 pid;
	u8 event_type;
	char comm[COMPAT_TASK_COMM_LEN];
};

static __always_inline void update_dirty_stats(u64 dirty_age_ns)
{
	u32 key = 0;
	struct page_cache_stats *stats;

	stats = bpf_map_lookup_elem(&page_stats_map, &key);
	if (!stats)
		return;

	stats->dirty_age_sum += dirty_age_ns;
	if (dirty_age_ns > stats->dirty_age_max)
		stats->dirty_age_max = dirty_age_ns;
}

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(trace_add_to_page_cache_lru, struct page *page)
{
	u32 key = 0;
	struct page_cache_stats *stats;

	stats = bpf_map_lookup_elem(&page_stats_map, &key);
	if (stats)
		stats->clean_pages++;

	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(trace_mark_buffer_dirty, struct buffer_head *bh)
{
	struct page_key key = {};
	struct dirty_page_info info = {};
	u64 ts = bpf_ktime_get_ns();
	u64 page_addr;

	page_addr = (u64)BPF_CORE_READ(bh, b_page);
	key.page_addr = page_addr;

	info.mark_dirty_ts = ts;
	info.pid = bpf_get_current_pid_tgid() >> 32;
	info.state = 0;
	bpf_get_current_comm(info.comm, sizeof(info.comm));

	bpf_map_update_elem(&dirty_page_map, &key, &info, COMPAT_BPF_ANY);

	u32 stats_key = 0;
	struct page_cache_stats *stats;
	stats = bpf_map_lookup_elem(&page_stats_map, &stats_key);
	if (stats) {
		stats->dirty_pages++;
		if (stats->clean_pages > 0)
			stats->clean_pages--;
	}

	return 0;
}

SEC("kprobe/writepage")
int BPF_KPROBE(trace_writepage, struct page *page)
{
	struct page_key key = {};
	struct dirty_page_info *info;
	u64 ts = bpf_ktime_get_ns();
	u64 page_addr = (u64)page;

	key.page_addr = page_addr;

	info = bpf_map_lookup_elem(&dirty_page_map, &key);
	if (info) {
		info->writeback_ts = ts;
		info->state = 1;

		u64 dirty_age = ts - info->mark_dirty_ts;
		update_dirty_stats(dirty_age);

		u32 stats_key = 0;
		struct page_cache_stats *stats;
		stats = bpf_map_lookup_elem(&page_stats_map, &stats_key);
		if (stats) {
			stats->dirty_pages--;
			stats->writeback_pages++;
		}
	}

	return 0;
}

SEC("kprobe/__delete_from_page_cache")
int BPF_KPROBE(trace_delete_from_page_cache, struct page *page)
{
	struct page_key key = {};
	u64 page_addr = (u64)page;

	key.page_addr = page_addr;

	bpf_map_delete_elem(&dirty_page_map, &key);

	u32 stats_key = 0;
	struct page_cache_stats *stats;
	stats = bpf_map_lookup_elem(&page_stats_map, &stats_key);
	if (stats)
		stats->invalidate_count++;

	return 0;
}

SEC("kprobe/invalidate_inode_page")
int BPF_KPROBE(trace_invalidate_inode_page, struct page *page)
{
	u32 key = 0;
	struct page_cache_stats *stats;

	stats = bpf_map_lookup_elem(&page_stats_map, &key);
	if (stats)
		stats->invalidate_count++;

	return 0;
}

SEC("kretprobe/writepage")
int BPF_KRETPROBE(trace_writepage_ret, int ret)
{
	if (ret != 0) {
		u32 key = 0;
		struct page_cache_stats *stats;
		stats = bpf_map_lookup_elem(&page_stats_map, &key);
		if (stats)
			stats->writeback_fail++;
	}

	return 0;
}