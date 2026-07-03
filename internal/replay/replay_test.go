package replay_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"powd/internal/replay"
)

var (
	now    = time.Unix(1_720_000_000, 0)
	expiry = now.Add(2 * time.Minute)
)

func TestFirstRedemptionOnly(t *testing.T) {
	c := replay.New(16)
	if !c.Redeem(now, "a", expiry) {
		t.Fatal("first redemption reported as replay")
	}
	if c.Redeem(now, "a", expiry) {
		t.Fatal("second redemption accepted")
	}
	if c.Redeem(now.Add(time.Minute), "a", expiry) {
		t.Fatal("later replay within TTL accepted")
	}
}

func TestIndependentIDs(t *testing.T) {
	c := replay.New(16)
	for _, id := range []string{"a", "b", "c"} {
		if !c.Redeem(now, id, expiry) {
			t.Errorf("first redemption of %q reported as replay", id)
		}
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

func TestExpiredEntriesArePruned(t *testing.T) {
	c := replay.New(16)
	c.Redeem(now, "old", expiry)

	later := expiry.Add(time.Second)
	if !c.Redeem(later, "new", later.Add(2*time.Minute)) {
		t.Fatal("fresh redemption reported as replay")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1 (expired entry should be pruned)", c.Len())
	}
}

func TestEvictionAtCapacity(t *testing.T) {
	c := replay.New(3)
	for i := 0; i < 4; i++ {
		if !c.Redeem(now, fmt.Sprintf("id%d", i), expiry) {
			t.Fatalf("redemption %d reported as replay", i)
		}
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
	// The oldest entry was evicted, so — by design, fail-open — its
	// replay is no longer detected.
	if !c.Redeem(now, "id0", expiry) {
		t.Error("evicted entry still remembered")
	}
	// The newest entries are still protected.
	if c.Redeem(now, "id3", expiry) {
		t.Error("recent entry was evicted, want oldest-first eviction")
	}
}

func TestDefaultCapacity(t *testing.T) {
	c := replay.New(0)
	if !c.Redeem(now, "a", expiry) || c.Redeem(now, "a", expiry) {
		t.Error("cache with default capacity does not remember redemptions")
	}
}

// TestConcurrentSameID is the reason Redeem is one atomic operation:
// many goroutines racing to redeem one challenge must yield exactly one
// success. Run with -race.
func TestConcurrentSameID(t *testing.T) {
	c := replay.New(1024)
	const workers = 64

	var wg sync.WaitGroup
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- c.Redeem(now, "contested", expiry)
		}()
	}
	wg.Wait()
	close(results)

	wins := 0
	for ok := range results {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("%d concurrent redemptions succeeded, want exactly 1", wins)
	}
}

func TestConcurrentDistinctIDs(t *testing.T) {
	c := replay.New(1024)
	const workers = 64

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		id := fmt.Sprintf("id%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !c.Redeem(now, id, expiry) {
				t.Errorf("first redemption of %q reported as replay", id)
			}
		}()
	}
	wg.Wait()
	if c.Len() != workers {
		t.Errorf("Len = %d, want %d", c.Len(), workers)
	}
}
