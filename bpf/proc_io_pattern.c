#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 1024

struct proc_io_key {
	u32 pid;
};

struct proc_io_stats {
	u64 write_bytes;
	u64 read_bytes;
	u64 write_count;
	u64 read_count;
	u64 fsync_count;
	u64 fsync_latency_sum;
	u64 fsync_latency_max;
	u64 partial_write_count;
	u64 fsync_retry_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct proc_io_key);
	__type(value, struct proc_io_stats);
} proc_io_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} fsync_track_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	struct proc_io_stats new_stats = {};

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats) {
		bpf_map_update_elem(&proc_io_map, &key, &new_stats, COMPAT_BPF_ANY);
		stats = bpf_map_lookup_elem(&proc_io_map, &key);
		if (!stats)
			return 0;
	}

	stats->write_count++;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	ssize_t ret = ctx->ret;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats)
		return 0;

	if (ret > 0)
		stats->write_bytes += ret;

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	struct proc_io_stats new_stats = {};

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats) {
		bpf_map_update_elem(&proc_io_map, &key, &new_stats, COMPAT_BPF_ANY);
		stats = bpf_map_lookup_elem(&proc_io_map, &key);
		if (!stats)
			return 0;
	}

	stats->read_count++;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	ssize_t ret = ctx->ret;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats)
		return 0;

	if (ret > 0)
		stats->read_bytes += ret;

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_sys_enter_fsync(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	struct proc_io_stats new_stats = {};

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats) {
		bpf_map_update_elem(&proc_io_map, &key, &new_stats, COMPAT_BPF_ANY);
		stats = bpf_map_lookup_elem(&proc_io_map, &key);
		if (!stats)
			return 0;
	}

	stats->fsync_count++;
	bpf_map_update_elem(&fsync_track_map, &pid, &ts, COMPAT_BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int trace_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 ts = bpf_ktime_get_ns();
	int ret = ctx->ret;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	u64 *start_ts;

	start_ts = bpf_map_lookup_elem(&fsync_track_map, &pid);
	if (!start_ts)
		return 0;

	u64 latency = ts - *start_ts;

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (stats) {
		stats->fsync_latency_sum += latency;
		if (latency > stats->fsync_latency_max)
			stats->fsync_latency_max = latency;
		if (ret != 0)
			stats->fsync_retry_count++;
	}

	bpf_map_delete_elem(&fsync_track_map, &pid);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	struct proc_io_stats new_stats = {};

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (!stats) {
		bpf_map_update_elem(&proc_io_map, &key, &new_stats, COMPAT_BPF_ANY);
		stats = bpf_map_lookup_elem(&proc_io_map, &key);
		if (!stats)
			return 0;
	}

	stats->fsync_count++;
	bpf_map_update_elem(&fsync_track_map, &pid, &ts, COMPAT_BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int trace_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 ts = bpf_ktime_get_ns();
	int ret = ctx->ret;
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;
	u64 *start_ts;

	start_ts = bpf_map_lookup_elem(&fsync_track_map, &pid);
	if (!start_ts)
		return 0;

	u64 latency = ts - *start_ts;

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (stats) {
		stats->fsync_latency_sum += latency;
		if (latency > stats->fsync_latency_max)
			stats->fsync_latency_max = latency;
		if (ret != 0)
			stats->fsync_retry_count++;
	}

	bpf_map_delete_elem(&fsync_track_map, &pid);

	return 0;
}