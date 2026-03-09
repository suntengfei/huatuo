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
	tracing.RegisterEventTracing("page_cache_health", newPageCacheHealth)
}

func newPageCacheHealth() (*tracing.EventTracingAttr, error) {
	cpuPossible, err := numcpus.GetPossible()
	if err != nil {
		return nil, fmt.Errorf("get possible cpus: %w", err)
	}

	return &tracing.EventTracingAttr{
		TracingData: &pageCacheHealth{
			cpuPossible: cpuPossible,
		},
		Internal: 10,
		Flag:     tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/page_cache_health.c -o $BPF_DIR/page_cache_health.o

type pageCacheHealth struct {
	bpf         bpf.BPF
	running     atomic.Bool
	cpuPossible int
}

type pageCacheStats struct {
	DirtyEvents     uint64
	WritebackEvents uint64
	PagesDirtied    uint64
	PagesWritten    uint64
}

func (c *pageCacheHealth) Update() ([]*metric.Data, error) {
	if !c.running.Load() {
		return nil, nil
	}

	items, err := c.bpf.DumpMapByName("page_stats_map")
	if err != nil {
		return nil, fmt.Errorf("dump map page_stats_map: %w", err)
	}

	var stats pageCacheStats
	if len(items) > 0 {
		perCPUStats := make([]pageCacheStats, c.cpuPossible)
		buf := bytes.NewReader(items[0].Value)
		if err := binary.Read(buf, binary.LittleEndian, &perCPUStats); err != nil {
			return nil, fmt.Errorf("read per-cpu stats: %w", err)
		}

		for _, cpuStat := range perCPUStats {
			stats.DirtyEvents += cpuStat.DirtyEvents
			stats.WritebackEvents += cpuStat.WritebackEvents
			stats.PagesDirtied += cpuStat.PagesDirtied
			stats.PagesWritten += cpuStat.PagesWritten
		}
	}

	dirtyWritebackGap := int64(stats.DirtyEvents) - int64(stats.WritebackEvents)
	if dirtyWritebackGap < 0 {
		dirtyWritebackGap = 0
	}

	cfg := conf.Get().MetricCollector.DiskHealth
	if cfg.Enabled && cfg.PageCache.Enabled {
		if dirtyWritebackGap > int64(cfg.PageCache.DirtyWritebackGapThreshold) {
			log.Warnf("Page cache dirty-writeback gap %d above threshold %d",
				dirtyWritebackGap, cfg.PageCache.DirtyWritebackGapThreshold)
		}
	}

	return []*metric.Data{
		metric.NewGaugeData("page_cache_dirty_events", float64(stats.DirtyEvents), "Number of dirty page events", nil),
		metric.NewGaugeData("page_cache_writeback_events", float64(stats.WritebackEvents), "Number of writeback events", nil),
		metric.NewGaugeData("page_cache_dirty_writeback_gap", float64(dirtyWritebackGap), "Gap between dirty and writeback events", nil),
		metric.NewGaugeData("page_cache_pages_dirtied", float64(stats.PagesDirtied), "Total pages dirtied", nil),
		metric.NewGaugeData("page_cache_pages_written", float64(stats.PagesWritten), "Total pages written", nil),
	}, nil
}

func (c *pageCacheHealth) Start(ctx context.Context) error {
	cfg := conf.Get().MetricCollector.DiskHealth
	if !cfg.Enabled || !cfg.PageCache.Enabled {
		log.Infof("page_cache_health disabled by config")
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
