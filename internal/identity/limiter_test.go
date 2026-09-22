package identity

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterRefillAndMemoryBound(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(2)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("one", 3, time.Minute) {
			t.Fatal("premature refusal")
		}
	}
	if l.Allow("one", 3, time.Minute) {
		t.Fatal("burst bypass")
	}
	now = now.Add(time.Minute)
	if !l.Allow("one", 3, time.Minute) {
		t.Fatal("no refill")
	}
	if !l.Allow("two", 3, time.Minute) || l.Allow("three", 3, time.Minute) {
		t.Fatal("unbounded limiter")
	}
	now = now.Add(2 * time.Hour)
	if !l.Allow("three", 3, time.Minute) {
		t.Fatal("idle buckets not collected")
	}
	if len(l.entries) > 2 {
		t.Fatal("memory bound exceeded")
	}
}
func TestLimiterConcurrentBurst(t *testing.T) {
	l := NewLimiter(10)
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("user", 8, time.Hour) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 8 {
		t.Fatalf("allowed %d", allowed.Load())
	}
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprint(i), 1, time.Hour)
	}
	if len(l.entries) > 10 {
		t.Fatal("memory cap exceeded")
	}
}
