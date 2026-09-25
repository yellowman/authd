package identity

import (
	"container/list"
	"sync"
	"time"
)

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiterEntry struct {
	key    string
	bucket bucket
}

// Limiter is bounded and process-local. Least-recently-used buckets are
// evicted on saturation so unrelated new identities can still sign in.
// It does not claim cross-process rate coordination.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	recent  list.List
	max     int
	now     func() time.Time
}

func NewLimiter(max int) *Limiter {
	if max < 1 {
		max = 1
	}
	return &Limiter{entries: map[string]*list.Element{}, max: max, now: time.Now}
}
func (l *Limiter) Allow(key string, burst int, period time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	element, ok := l.entries[key]
	var b bucket
	if !ok {
		if len(l.entries) >= l.max {
			oldest := l.recent.Back()
			delete(l.entries, oldest.Value.(*limiterEntry).key)
			l.recent.Remove(oldest)
		}
		b = bucket{tokens: float64(burst), updated: now}
		element = l.recent.PushFront(&limiterEntry{key: key})
		l.entries[key] = element
	} else {
		l.recent.MoveToFront(element)
		b = element.Value.(*limiterEntry).bucket
	}
	b.tokens += now.Sub(b.updated).Seconds() / period.Seconds()
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.updated = now
	if b.tokens < 1 {
		element.Value.(*limiterEntry).bucket = b
		return false
	}
	b.tokens--
	element.Value.(*limiterEntry).bucket = b
	return true
}
