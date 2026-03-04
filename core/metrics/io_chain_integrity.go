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
)

func init() {
	tracing.RegisterEventTracing("io_chain_integrity", newIOChainIntegrity)
}

func newIOChainIntegrity() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &ioChainIntegrity{},
		Internal:    10,
		Flag:        tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/io_chain_tracing.c -o $BPF_DIR/io_chain_tracing.o

type ioChainIntegrity struct {
	bpf     bpf.BPF
	running atomic.Bool
}

type ioChainStats struct {
	TotalRequests     uint64
	CompletedRequests uint64
	OrphanRequests    uint64
	LatencySum        uint64
	LatencyMax        uint64
	SizeMismatch      uint64
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
		buf := bytes.NewReader(items[0].Value)
		if err := binary.Read(buf, binary.LittleEndian, &stats); err != nil {
			return nil, err
		}
	}

	var completeRate float64
	if stats.TotalRequests > 0 {
		completeRate = float64(stats.CompletedRequests) / float64(stats.TotalRequests)
	}

	var latencyAvg float64
	if stats.CompletedRequests > 0 {
		latencyAvg = float64(stats.LatencySum) / float64(stats.CompletedRequests) / 1000000
	}

	latencyMaxMs := float64(stats.LatencyMax) / 1000000

	cfg := conf.Get().MetricCollector.DiskHealth
	if cfg.Enabled && cfg.IOChain.Enabled {
		if completeRate < cfg.IOChain.CompleteRateThreshold {
			log.Warnf("IO chain complete rate %.4f below threshold %.4f",
				completeRate, cfg.IOChain.CompleteRateThreshold)
		}
		if stats.OrphanRequests > uint64(cfg.IOChain.OrphanCountThreshold) {
			log.Warnf("IO chain orphan requests %d above threshold %d",
				stats.OrphanRequests, cfg.IOChain.OrphanCountThreshold)
		}
		if latencyMaxMs > float64(cfg.IOChain.LatencyP99ThresholdMs) {
			log.Warnf("IO chain max latency %.2fms above threshold %dms",
				latencyMaxMs, cfg.IOChain.LatencyP99ThresholdMs)
		}
	}

	return []*metric.Data{
		metric.NewGaugeData("io_chain_complete_rate", completeRate, "IO chain completion rate", nil),
		metric.NewGaugeData("io_chain_orphan_count", float64(stats.OrphanRequests), "Orphan IO requests count", nil),
		metric.NewGaugeData("io_chain_latency_avg_ms", latencyAvg, "IO chain average latency in ms", nil),
		metric.NewGaugeData("io_chain_latency_max_ms", latencyMaxMs, "IO chain max latency in ms", nil),
		metric.NewGaugeData("io_chain_size_mismatch", float64(stats.SizeMismatch), "IO size mismatch count", nil),
		metric.NewGaugeData("io_chain_total_requests", float64(stats.TotalRequests), "Total IO requests", nil),
		metric.NewGaugeData("io_chain_completed_requests", float64(stats.CompletedRequests), "Completed IO requests", nil),
	}, nil
}

func (c *ioChainIntegrity) Start(ctx context.Context) error {
	obj, err := bpf.LoadBpf(bpf.ThisBpfOBJ(), nil)
	if err != nil {
		return err
	}
	defer obj.Close()

	if err := obj.Attach(); err != nil {
		return err
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	obj.WaitDetachByBreaker(childCtx, cancel)

	c.bpf = obj
	c.running.Store(true)

	<-childCtx.Done()
	c.running.Store(false)
	return nil
}
