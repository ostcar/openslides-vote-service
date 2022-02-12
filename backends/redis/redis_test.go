package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenSlides/openslides-vote-service/internal/backends/redis"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/test"
	"github.com/ory/dockertest/v3"
)

func startRedis(t *testing.T) (string, func()) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	resource, err := pool.Run("redis", "6.2", nil)
	if err != nil {
		t.Fatalf("Could not start redis container: %s", err)
	}

	return resource.GetPort("6379/tcp"), func() {
		if err = pool.Purge(resource); err != nil {
			t.Fatalf("Could not purge redis container: %s", err)
		}
	}
}

func TestImplementBackendInterface(t *testing.T) {
	port, close := startRedis(t)
	defer close()

	r := redis.New("localhost:" + port)
	r.Wait(context.Background())
	t.Logf("Redis port: %s", port)

	test.Backend(t, r)
}

func TestCounterInterface(t *testing.T) {
	port, close := startRedis(t)
	defer close()

	r := redis.New("localhost:" + port)
	r.Wait(context.Background())
	t.Logf("Redis port: %s", port)

	t.Run("CountAdd", func(t *testing.T) {
		defer r.ClearAll(context.Background())

		if err := r.CountAdd(context.Background(), 5); err != nil {
			t.Fatalf("adding returned unexpected error: %v", err)
		}

		_, counter, err := r.Counters(context.Background(), 0, false)
		if err != nil {
			t.Fatalf("reading counter: %v", err)
		}

		if len(counter) != 1 || counter[5] != 1 {
			t.Errorf("got %v, expected map[5: 1]", counter)
		}
	})

	t.Run("CountClear", func(t *testing.T) {
		defer r.ClearAll(context.Background())

		if err := r.CountAdd(context.Background(), 5); err != nil {
			t.Fatalf("adding returned unexpected error: %v", err)
		}

		if err := r.CountClear(context.Background(), 5); err != nil {
			t.Fatalf("clearing returned unexpected error: %v", err)
		}

		_, counter, err := r.Counters(context.Background(), 0, false)
		if err != nil {
			t.Fatalf("reading counter: %v", err)
		}

		if len(counter) != 1 || counter[5] != 0 {
			t.Errorf("got %v, expected map[5:0]", counter)
		}
	})

	t.Run("Counters", func(t *testing.T) {
		t.Run("With id 0", func(t *testing.T) {
			defer r.ClearAll(context.Background())

			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 2)

			newID, counter, err := r.Counters(context.Background(), 0, false)
			if err != nil {
				t.Fatalf("reading counter: %v", err)
			}

			if newID != 3 {
				t.Errorf("counters returned new id %d, expected 3", newID)
			}

			if len(counter) != 2 || counter[1] != 2 || counter[2] != 1 {
				t.Errorf("counters returned %v, expected map[1:2,2:1]", counter)
			}
		})

		t.Run("On empty db", func(t *testing.T) {
			defer r.ClearAll(context.Background())

			newID, counter, err := r.Counters(context.Background(), 0, false)
			if err != nil {
				t.Fatalf("reading counter: %v", err)
			}

			if newID != 0 {
				t.Errorf("counters returned new id %d, expected 0", newID)
			}

			if len(counter) != 0 {
				t.Errorf("counters returned %v, expected map[]", counter)
			}
		})

		t.Run("With id", func(t *testing.T) {
			defer r.ClearAll(context.Background())

			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 2)

			newID, counter, err := r.Counters(context.Background(), 2, false)
			if err != nil {
				t.Fatalf("reading counter: %v", err)
			}

			if newID != 3 {
				t.Errorf("counters returned new id %d, expected 3", newID)
			}

			if len(counter) != 1 || counter[2] != 1 {
				t.Errorf("counters returned %v, expected map[2:1]", counter)
			}
		})

		t.Run("With max id", func(t *testing.T) {
			defer r.ClearAll(context.Background())

			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 1)
			r.CountAdd(context.Background(), 2)

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()

			newID, counter, err := r.Counters(ctx, 3, true)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expect deadline exceeded error, got: %v", err)
			}

			if newID != 0 {
				t.Errorf("counters returned new id %d, expected 0", newID)
			}

			if len(counter) != 0 {
				t.Errorf("counters returned %v, expected empty map", counter)
			}
		})

		t.Run("after clear", func(t *testing.T) {
			defer r.ClearAll(context.Background())

			r.CountAdd(context.Background(), 1)
			r.CountClear(context.Background(), 1)

			newID, counter, err := r.Counters(context.Background(), 1, false)
			if err != nil {
				t.Fatalf("reading counter: %v", err)
			}

			if newID != 2 {
				t.Errorf("counters returned new id %d, expected 2", newID)
			}

			if len(counter) != 1 || counter[1] != 0 {
				t.Errorf("counters returned %v, expected map[1:0]", counter)
			}
		})
	})
}
