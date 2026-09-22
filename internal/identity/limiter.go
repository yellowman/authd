package identity

import (
	"sync"
	"time"
)

type bucket struct {
	tokens  float64
	updated time.Time
}

// Limiter is bounded and process-local. A full table fails closed rather than
// evicting hot buckets. It does not claim cross-process rate coordination.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]bucket
	max     int
	now     func() time.Time
}

func NewLimiter(max int) *Limiter {
	return &Limiter{entries: map[string]bucket{}, max: max, now: time.Now}
}
func (l *Limiter) Allow(key string, burst int, period time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.max {
			for k, v := range l.entries {
				if now.Sub(v.updated) > time.Hour {
					delete(l.entries, k)
				}
			}
		}
		if len(l.entries) >= l.max {
			return false
		}
		b = bucket{tokens: float64(burst), updated: now}
	}
	b.tokens += now.Sub(b.updated).Seconds() / period.Seconds()
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.updated = now
	if b.tokens < 1 {
		l.entries[key] = b
		return false
	}
	b.tokens--
	l.entries[key] = b
	return true
}
