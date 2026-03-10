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
	"sync/atomic"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/conf"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/pkg/metric"
	"huatuo-bamai/pkg/tracing"

	"github.com/tklauser/numcpus"
)

func init() {
	tracing.RegisterEventTracing("io_chain_integrity", newIOChainIntegrity)
}

func newIOChainIntegrity() (*tracing.EventTracingAttr, error) {
	cpuPossible, err := numcpus.GetPossible()
	if err != nil {
		return nil, fmt.Errorf("get possible cpus: %w", err)
	}

	return &tracing.EventTracingAttr{
		TracingData: &ioChainIntegrity{
			cpuPossible:  cpuPossible,
			perCPUStats:  make([]ioChainStats, cpuPossible),
			statsBuf:     make([]byte, 0, 1024),
		},
		Internal: 10,
		Flag:     tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/io_chain_integrity.c -o $BPF_DIR/io_chain_integrity.o

type ioChainIntegrity struct {
	bpf         bpf.BPF
	running     atomic.Bool
	cpuPossible int
	perCPUStats []ioChainStats
	statsBuf    []byte
}

type ioChainStats struct {
	TotalRequests     uint64
	CompletedRequests uint64
	LatencySum        uint64
	LatencyMax        uint64
	SizeMismatch      uint64
	OrphanCompletes   uint64
}

func (c *ioChainIntegrity) Update() ([]*metric.Data, error) {
	if !c.running.Load() {
		return nil, nil
	}

	items, err := c.bpf.DumpMapByName("io_stats_map")
	if err != nil {
		return nil, fmt.Errorf("dump map io_stats_map: %w", err)
	}

	var stats ioChainStats
	if len(items) > 0 {
		for i := range c.perCPUStats {
			c.perCPUStats[i] = ioChainStats{}
		}

		buf := bytes.NewReader(items[0].Value)
		if err := binary.Read(buf, binary.LittleEndian, &c.perCPUStats); err != nil {
			return nil, fmt.Errorf("read per-cpu stats: %w", err)
		}

		for _, cpuStat := range c.perCPUStats {
			stats.TotalRequests += cpuStat.TotalRequests
			stats.CompletedRequests += cpuStat.CompletedRequests
			stats.LatencySum += cpuStat.LatencySum
			if cpuStat.LatencyMax > stats.LatencyMax {
				stats.LatencyMax = cpuStat.LatencyMax
			}
			stats.SizeMismatch += cpuStat.SizeMismatch
			stats.OrphanCompletes += cpuStat.OrphanCompletes
		}
	}

	var matchRate float64
	totalCompletes := stats.CompletedRequests + stats.OrphanCompletes
	if totalCompletes > 0 {
		matchRate = float64(stats.CompletedRequests) / float64(totalCompletes)
	}

	var latencyAvg float64
	if stats.CompletedRequests > 0 {
		latencyAvg = float64(stats.LatencySum) / float64(stats.CompletedRequests) / 1000000
	}

	latencyMaxMs := float64(stats.LatencyMax) / 1000000

	cfg := conf.Get().MetricCollector.DiskHealth
	if cfg.Enabled && cfg.IOChain.Enabled {
		if matchRate < cfg.IOChain.CompleteRateThreshold {
			log.Warnf("IO chain match rate %.4f below threshold %.4f",
				matchRate, cfg.IOChain.CompleteRateThreshold)
		}
		if stats.OrphanCompletes > uint64(cfg.IOChain.OrphanCountThreshold) {
			log.Warnf("IO chain orphan completes %d above threshold %d",
				stats.OrphanCompletes, cfg.IOChain.OrphanCountThreshold)
		}
		if latencyMaxMs > float64(cfg.IOChain.LatencyP99ThresholdMs) {
			log.Warnf("IO chain max latency %.2fms above threshold %dms",
				latencyMaxMs, cfg.IOChain.LatencyP99ThresholdMs)
		}
	}

	return []*metric.Data{
		metric.NewGaugeData("io_chain_match_rate", matchRate, "Rate of IO completes that matched original requests", nil),
		metric.NewGaugeData("io_chain_latency_avg_ms", latencyAvg, "IO chain average latency in ms", nil),
		metric.NewGaugeData("io_chain_latency_max_ms", latencyMaxMs, "IO chain max latency in ms", nil),
		metric.NewGaugeData("io_chain_size_mismatch", float64(stats.SizeMismatch), "IO size mismatch count", nil),
		metric.NewGaugeData("io_chain_orphan_completes", float64(stats.OrphanCompletes), "IO completes without matching request", nil),
		metric.NewGaugeData("io_chain_total_requests", float64(stats.TotalRequests), "Total IO requests issued", nil),
		metric.NewGaugeData("io_chain_completed_requests", float64(stats.CompletedRequests), "IO requests completed with match", nil),
		metric.NewGaugeData("io_chain_total_completes", float64(totalCompletes), "Total IO completes", nil),
	}, nil
}

func (c *ioChainIntegrity) Start(ctx context.Context) error {
	cfg := conf.Get().MetricCollector.DiskHealth
	if !cfg.Enabled || !cfg.IOChain.Enabled {
		log.Infof("io_chain_integrity disabled by config")
		return nil
	}

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
