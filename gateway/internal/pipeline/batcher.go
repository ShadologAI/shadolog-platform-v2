// Package pipeline provides event batching and multi-sink flushing for the v4 Gateway.
//
// Events are buffered in memory and flushed either when the buffer reaches
// maxSize (1000) or on a periodic timer (1s). Sinks are called in order:
// NATS JetStream first (primary durable buffer), then ClickHouse (metadata).
//
// Graceful shutdown flushes all remaining events before returning.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// Sink is the interface for flushing batched events to a downstream store.
type Sink interface {
	Flush(ctx context.Context, events []*models.Event) error
}

// Batcher buffers events and flushes them periodically or when the buffer is full.
type Batcher struct {
	mu       sync.Mutex
	buffer   []*models.Event
	sinks    []Sink
	maxSize  int
	interval time.Duration
	logger   *slog.Logger
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewBatcher creates a batcher that flushes on size (maxSize) or timer (interval).
// Default: maxSize=1000, interval=1s.
func NewBatcher(maxSize int, interval time.Duration, logger *slog.Logger, sinks ...Sink) *Batcher {
	return &Batcher{
		buffer:   make([]*models.Event, 0, maxSize),
		sinks:    sinks,
		maxSize:  maxSize,
		interval: interval,
		logger:   logger,
		done:     make(chan struct{}),
	}
}

// Start begins the periodic flush goroutine.
func (b *Batcher) Start() {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		ticker := time.NewTicker(b.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.flush()
			case <-b.done:
				b.flush() // final flush on shutdown
				return
			}
		}
	}()
}

// Stop signals the batcher to flush remaining events and stop.
func (b *Batcher) Stop() {
	close(b.done)
	b.wg.Wait()
}

// Add enqueues an event. If buffer reaches maxSize, triggers immediate flush.
func (b *Batcher) Add(event *models.Event) {
	b.mu.Lock()
	b.buffer = append(b.buffer, event)
	shouldFlush := len(b.buffer) >= b.maxSize
	b.mu.Unlock()

	if shouldFlush {
		b.flush()
	}
}

func (b *Batcher) flush() {
	b.mu.Lock()
	if len(b.buffer) == 0 {
		b.mu.Unlock()
		return
	}
	events := b.buffer
	b.buffer = make([]*models.Event, 0, b.maxSize)
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, sink := range b.sinks {
		if err := sink.Flush(ctx, events); err != nil {
			b.logger.Error("flush failed", "sink", fmt.Sprintf("%T", sink), "count", len(events), "error", err)
		}
	}

	b.logger.Info("flushed events", "count", len(events))
}

// Pending returns the current number of buffered events (for health checks).
func (b *Batcher) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buffer)
}
