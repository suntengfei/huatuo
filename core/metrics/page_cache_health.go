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
	tracing.RegisterEventTracing("page_cache_health", newPageCacheHealth)
}

func newPageCacheHealth() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &pageCacheHealth{},
		Internal:    10,
		Flag:        tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/page_cache_health.c -o $BPF_DIR/page_cache_health.o

type pageCacheHealth struct {
	bpf     bpf.BPF
	running atomic.Bool
}

type pageCacheStats struct {
	DirtyPages      uint64
	WritebackPages  uint64
	CleanPages      uint64
	InvalidateCount uint64
	DirtyAgeSum     uint64
	DirtyAgeMax     uint64
	WritebackFail   uint64
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
		buf := bytes.NewReader(items[0].Value)
		if err := binary.Read(buf, binary.LittleEndian, &stats); err != nil {
			return nil, err
		}
	}

	dirtyWritebackGap := int64(stats.DirtyPages) - int64(stats.WritebackPages)
	if dirtyWritebackGap < 0 {
		dirtyWritebackGap = 0
	}

	var dirtyAgeAvg float64
	if stats.DirtyPages > 0 {
		dirtyAgeAvg = float64(stats.DirtyAgeSum) / float64(stats.DirtyPages) / 1000000000
	}
	dirtyAgeMaxSec := float64(stats.DirtyAgeMax) / 1000000000

	cfg := conf.Get().MetricCollector.DiskHealth
	if cfg.Enabled && cfg.PageCache.Enabled {
		if dirtyWritebackGap > int64(cfg.PageCache.DirtyWritebackGapThreshold) {
			log.Warnf("Page cache dirty-writeback gap %d above threshold %d",
				dirtyWritebackGap, cfg.PageCache.DirtyWritebackGapThreshold)
		}
		if dirtyAgeMaxSec > float64(cfg.PageCache.DirtyAgeThresholdSec) {
			log.Warnf("Page cache max dirty age %.2fs above threshold %ds",
				dirtyAgeMaxSec, cfg.PageCache.DirtyAgeThresholdSec)
		}
		if stats.InvalidateCount > uint64(cfg.PageCache.InvalidateRateThreshold) {
			log.Warnf("Page cache invalidate count %d above threshold %d",
				stats.InvalidateCount, cfg.PageCache.InvalidateRateThreshold)
		}
	}

	return []*metric.Data{
		metric.NewGaugeData("page_cache_dirty_pages", float64(stats.DirtyPages), "Number of dirty pages", nil),
		metric.NewGaugeData("page_cache_writeback_pages", float64(stats.WritebackPages), "Number of pages in writeback", nil),
		metric.NewGaugeData("page_cache_dirty_writeback_gap", float64(dirtyWritebackGap), "Gap between dirty and writeback pages", nil),
		metric.NewGaugeData("page_cache_dirty_age_avg_sec", dirtyAgeAvg, "Average dirty page age in seconds", nil),
		metric.NewGaugeData("page_cache_dirty_age_max_sec", dirtyAgeMaxSec, "Max dirty page age in seconds", nil),
		metric.NewGaugeData("page_cache_invalidate_count", float64(stats.InvalidateCount), "Page invalidate count", nil),
		metric.NewGaugeData("page_cache_writeback_fail", float64(stats.WritebackFail), "Writeback failure count", nil),
		metric.NewGaugeData("page_cache_clean_pages", float64(stats.CleanPages), "Number of clean pages", nil),
	}, nil
}

func (c *pageCacheHealth) Start(ctx context.Context) error {
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
