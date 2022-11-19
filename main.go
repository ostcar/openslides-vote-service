package main

import (
	"context"
	"errors"
	"fmt"
	golog "log"
	"os"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/auth"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/environment"
	messageBusRedis "github.com/OpenSlides/openslides-autoupdate-service/pkg/redis"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/postgres"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/redis"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
	"github.com/OpenSlides/openslides-vote-service/internal/vote"
	"github.com/alecthomas/kong"
)

//go:generate  sh -c "go run main.go build-doc > environment.md"

var (
	envVotePort = environment.NewVariable("VOTE_PORT", "9013", "Port on which the service listen on.")

	envBackendFast = environment.NewVariable("VOTE_BACKEND_FAST", "redis", "The backend used for fast polls. Possible backends are redis, postgres or memory.")
	envBackendLong = environment.NewVariable("VOTE_BACKEND_LONG", "postgres", "The backend used for long polls.")

	envRedisHost = environment.NewVariable("VOTE_REDIS_HOST", "localhost", "Host of the redis used for the fast backend.")
	envRedisPort = environment.NewVariable("VOTE_REDIS_PORT", "6379", "Port of the redis used for the fast backend.")

	envPostgresHost     = environment.NewVariable("VOTE_DATABASE_HOST", "localhost", "Host of the postgres database used for long polls.")
	envPostgresPort     = environment.NewVariable("VOTE_DATABASE_PORT", "5432", "Port of the postgres database used for long polls.")
	envPostgresUser     = environment.NewVariable("VOTE_DATABASE_USER", "postgres", "Databasename of the postgres database used for long polls.")
	envPostgresDatabase = environment.NewVariable("VOTE_DATABASE_NAME", "", "")
	envPostgresPassword = environment.NewSecret("postgres_password", "Password of the postgres database used for long polls.")
)

var cli struct {
	Run      struct{} `cmd:"" help:"Runs the service." default:"withargs"`
	BuildDoc struct{} `cmd:"" help:"Build the environment documentation."`
	Health   struct {
		Host     string `help:"Host of the service" short:"h" default:"localhost"`
		Port     string `help:"Port of the service" short:"p" default:"9013" env:"VOTE_PORT"`
		UseHTTPS bool   `help:"Use https to connect to the service" short:"s"`
		Insecure bool   `help:"Accept invalid cert" short:"k"`
	} `cmd:"" help:"Runs a health check."`
}

func main() {
	ctx, cancel := environment.InterruptContext()
	defer cancel()
	log.SetInfoLogger(golog.Default())

	kongCTX := kong.Parse(&cli, kong.UsageOnError())
	switch kongCTX.Command() {
	case "run":
		if err := contextDone(run(ctx)); err != nil {
			handleError(err)
			os.Exit(1)
		}

	case "build-doc":
		if err := contextDone(buildDocu()); err != nil {
			handleError(err)
			os.Exit(1)
		}

	case "health":
		if err := contextDone(vote.HealthClient(ctx, cli.Health.UseHTTPS, cli.Health.Host, cli.Health.Port, cli.Health.Insecure)); err != nil {
			handleError(err)
			os.Exit(1)
		}
	}
}

func run(ctx context.Context) error {
	lookup := new(environment.ForProduction)

	service, err := initService(lookup)
	if err != nil {
		return fmt.Errorf("init services: %w", err)
	}

	return service(ctx)
}

func buildDocu() error {
	lookup := new(environment.ForDocu)

	if _, err := initService(lookup); err != nil {
		return fmt.Errorf("init services: %w", err)
	}

	doc, err := lookup.BuildDoc()
	if err != nil {
		return fmt.Errorf("build doc: %w", err)
	}

	fmt.Println(doc)
	return nil
}

// initService initializes all packages needed for the vote service.
//
// Returns a the service as callable.
func initService(lookup environment.Environmenter) (func(context.Context) error, error) {
	var backgroundTasks []func(context.Context, func(error))
	listenAddr := ":" + envVotePort.Value(lookup)

	// Redis as message bus for datastore and logout events.
	messageBus := messageBusRedis.New(lookup)

	// Datastore Service.
	datastoreService, dsBackground, err := datastore.New(lookup, messageBus)
	if err != nil {
		return nil, fmt.Errorf("init datastore: %w", err)
	}
	backgroundTasks = append(backgroundTasks, dsBackground)

	// Auth Service.
	authService, authBackground := auth.New(lookup, messageBus)
	backgroundTasks = append(backgroundTasks, authBackground)

	fastBackendStarter, longBackendStarter := buildBackends(lookup)

	service := func(ctx context.Context) error {
		for _, bg := range backgroundTasks {
			go bg(ctx, handleError)
		}

		fastBackend, err := fastBackendStarter(ctx)
		if err != nil {
			return fmt.Errorf("start fast backend: %w", err)
		}

		longBackend, err := longBackendStarter(ctx)
		if err != nil {
			return fmt.Errorf("start long backend: %w", err)
		}

		voteService := vote.New(fastBackend, longBackend, datastoreService)

		// Start http server.
		log.Info("Listen on %s\n", listenAddr)
		return vote.Run(ctx, listenAddr, authService, voteService)
	}

	return service, nil
}

// contextDone returns an empty error if the context is done or exceeded
func contextDone(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// handleError handles an error.
//
// Ignores context closed errors.
func handleError(err error) {
	if contextDone(err) == nil {
		return
	}

	log.Info("Error: %v", err)
}

func buildBackends(lookup environment.Environmenter) (fast, long func(context.Context) (vote.Backend, error)) {
	// All environment variables have to be called in this function and not in a
	// sub function. In other case they will not be included in the generated
	// file environment.md.

	buildMemory := func(_ context.Context) (vote.Backend, error) {
		return memory.New(), nil
	}

	redisAddr := envRedisHost.Value(lookup) + ":" + envRedisPort.Value(lookup)
	buildRedis := func(ctx context.Context) (vote.Backend, error) {
		r := redis.New(redisAddr)
		r.Wait(ctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return r, nil
	}

	postgresAddr := fmt.Sprintf(
		"postgres://%s@%s:%s/%s",
		envPostgresUser.Value(lookup),
		envPostgresHost.Value(lookup),
		envPostgresPort.Value(lookup),
		envPostgresDatabase.Value(lookup),
	)
	postgresPassword := envPostgresPassword.Value(lookup)
	buildPostgres := func(ctx context.Context) (vote.Backend, error) {
		p, err := postgres.New(ctx, postgresAddr, postgresPassword)
		if err != nil {
			return nil, fmt.Errorf("creating postgres connection pool: %w", err)
		}

		p.Wait(ctx)
		if err := p.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("creating shema: %w", err)
		}
		return p, nil
	}

	builder := map[string]func(context.Context) (vote.Backend, error){
		"memory":   buildMemory,
		"redis":    buildRedis,
		"postgres": buildPostgres,
	}

	fast = builder[envBackendFast.Value(lookup)]
	long = builder[envBackendLong.Value(lookup)]

	return fast, long
}
