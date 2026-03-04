#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 1024
#define MAX_TARGET_PROCS 16
#define MAX_COMM_LEN 16

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
	u64 last_offset;
	u64 offset_jumps;
	char comm[MAX_COMM_LEN];
};

struct fsync_track {
	u64 start_ts;
	u32 retry_count;
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
	__type(value, struct fsync_track);
} fsync_track_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

struct proc_io_alert {
	u64 timestamp;
	u32 pid;
	u64 value;
	u8 alert_type;
	char comm[MAX_COMM_LEN];
};

volatile const char target_procs[MAX_TARGET_PROCS][MAX_COMM_LEN] = {};
volatile const u32 target_proc_count = 0;

static __always_inline int is_target_process(const char *comm)
{
	if (target_proc_count == 0)
		return 1;

	for (int i = 0; i < MAX_TARGET_PROCS && i < target_proc_count; i++) {
		if (target_procs[i][0] == '\0')
			break;
		if (__builtin_memcmp(comm, target_procs[i], MAX_COMM_LEN) == 0)
			return 1;
	}

	return 0;
}

static __always_inline struct proc_io_stats *get_or_create_proc_stats(u32 pid, const char *comm)
{
	struct proc_io_key key = { .pid = pid };
	struct proc_io_stats *stats;

	stats = bpf_map_lookup_elem(&proc_io_map, &key);
	if (stats)
		return stats;

	struct proc_io_stats new_stats = {};
	__builtin_memcpy(new_stats.comm, comm, MAX_COMM_LEN);

	bpf_map_update_elem(&proc_io_map, &key, &new_stats, COMPAT_BPF_ANY);
	return bpf_map_lookup_elem(&proc_io_map, &key);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	stats->write_count++;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];
	ssize_t ret = ctx->ret;

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	if (ret > 0) {
		stats->write_bytes += ret;
	} else if (ret == 0) {
	} else {
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	stats->write_count++;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];
	ssize_t ret = ctx->ret;

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	if (ret > 0) {
		stats->write_bytes += ret;
	} else if (ret == 0) {
		stats->partial_write_count++;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	stats->read_count++;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];
	ssize_t ret = ctx->ret;

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (!stats)
		return 0;

	if (ret > 0) {
		stats->read_bytes += ret;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_sys_enter_fsync(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	char comm[MAX_COMM_LEN];
	u64 ts = bpf_ktime_get_ns();

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (stats)
		stats->fsync_count++;

	struct fsync_track track = {
		.start_ts = ts,
		.retry_count = 0,
	};
	bpf_map_update_elem(&fsync_track_map, &pid, &track, COMPAT_BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int trace_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 ts = bpf_ktime_get_ns();
	int ret = ctx->ret;
	char comm[MAX_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));

	if (!is_target_process(comm))
		return 0;

	struct fsync_track *track = bpf_map_lookup_elem(&fsync_track_map, &pid);
	if (!track)
		return 0;

	u64 latency = ts - track->start_ts;

	struct proc_io_stats *stats = get_or_create_proc_stats(pid, comm);
	if (stats) {
		stats->fsync_latency_sum += latency;
		if (latency > stats->fsync_latency_max)
			stats->fsync_latency_max = latency;

		if (ret != 0) {
			stats->fsync_retry_count++;
		}
	}

	bpf_map_delete_elem(&fsync_track_map, &pid);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx)
{
	return trace_sys_enter_fsync(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int trace_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx)
{
	return trace_sys_exit_fsync(ctx);
}
