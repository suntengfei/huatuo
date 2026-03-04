#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 65536
#define IO_CHAIN_TIMEOUT_NS 30000000000ULL

struct io_chain_key {
	u64 id;
};

struct io_chain_entry {
	u64 start_ts;
	u64 size;
	u64 offset;
	u32 pid;
	u32 dev;
	u8 stage;
	u8 completed;
	char comm[COMPAT_TASK_COMM_LEN];
};

struct io_chain_stats {
	u64 total_requests;
	u64 completed_requests;
	u64 orphan_requests;
	u64 latency_sum;
	u64 latency_max;
	u64 size_mismatch;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct io_chain_key);
	__type(value, struct io_chain_entry);
} io_chain_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct io_chain_stats);
} io_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

struct alert_event {
	u64 timestamp;
	u32 pid;
	u32 dev;
	u64 request_id;
	u64 latency_ns;
	u8 event_type;
	char comm[COMPAT_TASK_COMM_LEN];
};

static __always_inline u64 generate_request_id(u32 pid, u64 ts)
{
	return ((u64)pid << 32) | (ts & 0xFFFFFFFF);
}

static __always_inline void update_stats(u8 completed, u64 latency_ns)
{
	u32 key = 0;
	struct io_chain_stats *stats;

	stats = bpf_map_lookup_elem(&io_stats_map, &key);
	if (!stats)
		return;

	stats->total_requests++;
	if (completed) {
		stats->completed_requests++;
		stats->latency_sum += latency_ns;
		if (latency_ns > stats->latency_max)
			stats->latency_max = latency_ns;
	} else {
		stats->orphan_requests++;
	}
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	struct io_chain_key key = {};
	struct io_chain_entry entry = {};
	u64 ts = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();

	key.id = generate_request_id(id >> 32, ts);
	entry.start_ts = ts;
	entry.pid = id >> 32;
	entry.stage = 0;
	entry.completed = 0;

	bpf_get_current_comm(entry.comm, sizeof(entry.comm));
	bpf_map_update_elem(&io_chain_map, &key, &entry, COMPAT_BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	struct io_chain_key key = {};
	struct io_chain_entry *entry;
	u64 ts = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u64 latency_ns;

	key.id = generate_request_id(id >> 32, ts - IO_CHAIN_TIMEOUT_NS);

	entry = bpf_map_lookup_elem(&io_chain_map, &key);
	if (!entry)
		return 0;

	if (entry->stage >= 1) {
		entry->completed = 1;
		latency_ns = ts - entry->start_ts;
		update_stats(1, latency_ns);
	}

	bpf_map_delete_elem(&io_chain_map, &key);

	return 0;
}

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
	struct io_chain_key key = {};
	struct io_chain_entry *entry;
	u64 ts = bpf_ktime_get_ns();
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	key.id = generate_request_id(pid, ts - IO_CHAIN_TIMEOUT_NS);

	entry = bpf_map_lookup_elem(&io_chain_map, &key);
	if (entry && entry->stage == 0) {
		entry->stage = 1;
		entry->dev = ctx->dev;
		entry->size = ctx->bytes;
	}

	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_complete *ctx)
{
	struct io_chain_key key = {};
	struct io_chain_entry *entry;
	u64 ts = bpf_ktime_get_ns();
	u64 latency_ns;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 bytes;

	key.id = generate_request_id(pid, ts - IO_CHAIN_TIMEOUT_NS);

	entry = bpf_map_lookup_elem(&io_chain_map, &key);
	if (!entry)
		return 0;

	if (entry->stage >= 1) {
		entry->completed = 1;
		entry->stage = 2;
		latency_ns = ts - entry->start_ts;
		update_stats(1, latency_ns);

		bytes = (u64)ctx->nr_sector * 512;
		if (entry->size != bytes) {
			u32 key_stats = 0;
			struct io_chain_stats *stats;
			stats = bpf_map_lookup_elem(&io_stats_map, &key_stats);
			if (stats)
				stats->size_mismatch++;
		}
	}

	bpf_map_delete_elem(&io_chain_map, &key);

	return 0;
}

SEC("tracepoint/block/block_rq_insert")
int trace_block_rq_insert(struct trace_event_raw_block_rq *ctx)
{
	return 0;
}