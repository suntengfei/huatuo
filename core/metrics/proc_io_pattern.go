// Copyright 2025 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/conf"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/pkg/metric"
	"huatuo-bamai/pkg/tracing"
)

func init() {
	tracing.RegisterEventTracing("proc_io_pattern", newProcIOPattern)
}

func newProcIOPattern() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &procIOPattern{},
		Internal:    10,
		Flag:        tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/proc_io_pattern.c -o $BPF_DIR/proc_io_pattern.o

type procIOPattern struct {
	bpf     bpf.BPF
	running atomic.Bool
}

type procIOStats struct {
	WriteBytes      uint64
	ReadBytes       uint64
	WriteCount      uint64
	ReadCount       uint64
	FsyncCount      uint64
	FsyncLatencySum uint64
	FsyncLatencyMax uint64
	FsyncErrorCount uint64
}

type procIOKey struct {
	Pid     uint32
	Padding uint32
}

func getProcessComm(pid uint32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(data))
}

func (c *procIOPattern) Update() ([]*metric.Data, error) {
	if !c.running.Load() {
		return nil, nil
	}

	items, err := c.bpf.DumpMapByName("proc_io_map")
	if err != nil {
		return nil, fmt.Errorf("dump map proc_io_map: %w", err)
	}

	var metrics []*metric.Data
	var totalFsyncError uint64
	var totalFsyncLatencySum uint64
	var totalFsyncCount uint64
	var maxFsyncLatency uint64

	cfg := conf.Get().MetricCollector.DiskHealth

	for _, item := range items {
		var key procIOKey
		buf := bytes.NewReader(item.Key)
		if err := binary.Read(buf, binary.LittleEndian, &key); err != nil {
			continue
		}

		var stats procIOStats
		buf = bytes.NewReader(item.Value)
		if err := binary.Read(buf, binary.LittleEndian, &stats); err != nil {
			continue
		}

		comm := getProcessComm(key.Pid)
		labels := map[string]string{
			"pid":  fmt.Sprintf("%d", key.Pid),
			"comm": comm,
		}

		var fsyncLatencyAvg float64
		if stats.FsyncCount > 0 {
			fsyncLatencyAvg = float64(stats.FsyncLatencySum) / float64(stats.FsyncCount) / 1000000
		}
		fsyncLatencyMaxMs := float64(stats.FsyncLatencyMax) / 1000000

		metrics = append(metrics,
			metric.NewGaugeData("proc_io_write_bytes", float64(stats.WriteBytes), "Process write bytes", labels),
			metric.NewGaugeData("proc_io_read_bytes", float64(stats.ReadBytes), "Process read bytes", labels),
			metric.NewGaugeData("proc_io_write_count", float64(stats.WriteCount), "Process write count", labels),
			metric.NewGaugeData("proc_io_read_count", float64(stats.ReadCount), "Process read count", labels),
			metric.NewGaugeData("proc_io_fsync_count", float64(stats.FsyncCount), "Process fsync count", labels),
			metric.NewGaugeData("proc_io_fsync_latency_avg_ms", fsyncLatencyAvg, "Process fsync average latency in ms", labels),
			metric.NewGaugeData("proc_io_fsync_latency_max_ms", fsyncLatencyMaxMs, "Process fsync max latency in ms", labels),
			metric.NewGaugeData("proc_io_fsync_error_count", float64(stats.FsyncErrorCount), "Process fsync error count", labels),
		)

		totalFsyncError += stats.FsyncErrorCount
		totalFsyncLatencySum += stats.FsyncLatencySum
		totalFsyncCount += stats.FsyncCount
		if stats.FsyncLatencyMax > maxFsyncLatency {
			maxFsyncLatency = stats.FsyncLatencyMax
		}

		if cfg.Enabled && cfg.ProcIO.Enabled {
			if fsyncLatencyMaxMs > float64(cfg.ProcIO.FsyncLatencyThreshold) {
				log.Warnf("Process %s (pid=%d) fsync max latency %.2fms above threshold %dms",
					comm, key.Pid, fsyncLatencyMaxMs, cfg.ProcIO.FsyncLatencyThreshold)
			}
		}
	}

	var fsyncLatencyMaxGlobalMs float64
	if totalFsyncCount > 0 {
		fsyncLatencyMaxGlobalMs = float64(maxFsyncLatency) / 1000000
	}

	metrics = append(metrics,
		metric.NewGaugeData("proc_io_total_fsync_error_count", float64(totalFsyncError), "Total fsync error count across all processes", nil),
		metric.NewGaugeData("proc_io_fsync_latency_max_global_ms", fsyncLatencyMaxGlobalMs, "Max fsync latency in ms across all processes", nil),
	)

	return metrics, nil
}

func (c *procIOPattern) Start(ctx context.Context) error {
	obj, err := bpf.LoadBpf(bpf.ThisBpfOBJ(), nil)
	if err != nil {
		return err
	}

	if err := obj.Attach(); err != nil {
		obj.Close()
		return err
	}

	childCtx, cancel := context.WithCancel(ctx)

	obj.WaitDetachByBreaker(childCtx, cancel)

	c.bpf = obj
	c.running.Store(true)

	<-childCtx.Done()
	c.running.Store(false)

	return nil
}
