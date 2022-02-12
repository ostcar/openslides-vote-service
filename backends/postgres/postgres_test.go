package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/internal/backends/postgres"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/test"
	"github.com/ory/dockertest/v3"
)

func startPostgres(t *testing.T) (string, func()) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	runOpts := dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "11",
		Env: []string{
			"POSTGRES_USER=postgres",
			"POSTGRES_PASSWORD=password",
			"POSTGRES_DB=database",
		},
	}

	resource, err := pool.RunWithOptions(&runOpts)
	if err != nil {
		t.Fatalf("Could not start postgres container: %s", err)
	}

	return resource.GetPort("5432/tcp"), func() {
		if err = pool.Purge(resource); err != nil {
			t.Fatalf("Could not purge postgres container: %s", err)
		}
	}
}

func TestImplementBackendInterface(t *testing.T) {
	port, close := startPostgres(t)
	defer close()

	addr := fmt.Sprintf("postgres://postgres@localhost:%s/database", port)
	p, err := postgres.New(context.Background(), addr, "password")
	if err != nil {
		t.Fatalf("Creating postgres backend returned: %v", err)
	}
	defer p.Close()

	p.Wait(context.Background())
	if err := p.Migrate(context.Background()); err != nil {
		t.Fatalf("Creating db schema: %v", err)
	}

	t.Logf("Postgres port: %s", port)

	test.Backend(t, p)
}
