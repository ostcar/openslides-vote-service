package vote

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/auth"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore"
	messageBusRedis "github.com/OpenSlides/openslides-autoupdate-service/pkg/redis"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/postgres"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/redis"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

const authDebugKey = "auth-dev-key"

// Run starts the http server.
//
// The server is automaticly closed when ctx is done.
//
// The service is configured by the argument `environment`. It expect strings in
// the format `KEY=VALUE`, like the output from `os.Environmen()`.
func Run(ctx context.Context, environment []string) error {
	env := defaultEnv(environment)

	errHandler := func(err error) {
		log.Info("Error: %v", err)
	}

	messageBus, err := buildMessageBus(env)
	if err != nil {
		return fmt.Errorf("building message bus: %w", err)
	}

	ds, backgroud, err := initDatastore(ctx, env, messageBus, errHandler)
	if err != nil {
		return fmt.Errorf("building datastore: %w", err)
	}
	backgroud(ctx)

	auth, err := buildAuth(
		ctx,
		env,
		messageBus,
		errHandler,
	)
	if err != nil {
		return fmt.Errorf("building auth: %w", err)
	}

	fastBackend, longBackend, err := buildBackends(ctx, env)
	if err != nil {
		return fmt.Errorf("building backends: %w", err)
	}

	service := New(fastBackend, longBackend, ds)

	ticketProvider := func() (<-chan time.Time, func()) {
		ticker := time.NewTicker(time.Second)
		return ticker.C, ticker.Stop
	}

	mux := http.NewServeMux()
	handleStart(mux, service)
	handleStop(mux, service)
	handleClear(mux, service)
	handleClearAll(mux, service)
	handleVote(mux, service, auth)
	handleVoted(mux, service, auth)
	handleVoteCount(mux, service, ticketProvider)
	handleHealth(mux)

	listenAddr := ":" + env["VOTE_PORT"]
	srv := &http.Server{
		Addr:        listenAddr,
		Handler:     mux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	// Shutdown logic in separate goroutine.
	wait := make(chan error)
	go func() {
		// Wait for the context to be closed.
		<-ctx.Done()

		if err := srv.Shutdown(context.Background()); err != nil {
			wait <- fmt.Errorf("HTTP server shutdown: %w", err)
			return
		}
		wait <- nil
	}()

	log.Info("Listen on %s", listenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("HTTP Server failed: %v", err)
	}

	return <-wait
}

// defaultEnv parses the environment (output from os.Environ()) and sets specific
// defaut values.
func defaultEnv(environment []string) map[string]string {
	env := map[string]string{
		"VOTE_HOST":         "",
		"VOTE_PORT":         "9013",
		"VOTE_BACKEND_FAST": "redis",
		"VOTE_BACKEND_LONG": "postgres",
		"VOTE_REDIS_HOST":   "localhost",
		"VOTE_REDIS_PORT":   "6379",

		"DATASTORE_DATABASE_HOST": "localhost",
		"DATASTORE_DATABASE_PORT": "5432",
		"DATASTORE_DATABASE_USER": "openslides",
		"DATASTORE_DATABASE_NAME": "openslides",

		"SECRETS_PATH": "/run/secrets",

		"DATASTORE_READER_HOST":     "localhost",
		"DATASTORE_READER_PORT":     "9010",
		"DATASTORE_READER_PROTOCOL": "http",

		"AUTH":                 "fake",
		"AUTH_PROTOCOL":        "http",
		"AUTH_HOST":            "localhost",
		"AUTH_PORT":            "9004",
		"AUTH_TOKEN_KEY_FILE":  "/run/secrets/auth_token_key",
		"AUTH_COOKIE_KEY_FILE": "/run/secrets/auth_cookie_key",

		"MESSAGE_BUS_HOST": "localhost",
		"MESSAGE_BUS_PORT": "6379",
		"REDIS_TEST_CONN":  "true",

		"VOTE_DATABASE_USER":          "postgres",
		"VOTE_DATABASE_PASSWORD_FILE": "/run/secrets/vote_postgres_password",
		"VOTE_DATABASE_HOST":          "localhost",
		"VOTE_DATABASE_PORT":          "5432",
		"VOTE_DATABASE_NAME":          "vote",

		"OPENSLIDES_DEVELOPMENT": "false",
		"MAX_PARALLEL_KEYS":      "1000",
		"DATASTORE_TIMEOUT":      "3s",
	}

	for _, value := range environment {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			panic(fmt.Sprintf("Invalid value from environment(): %s", value))
		}

		env[parts[0]] = parts[1]
	}
	return env
}

func secret(env map[string]string, name string) ([]byte, error) {
	useDev, _ := strconv.ParseBool(env["OPENSLIDES_DEVELOPMENT"])

	if useDev {
		debugSecred := "openslides"
		switch name {
		case "auth_token_key":
			debugSecred = auth.DebugTokenKey
		case "auth_cookie_key":
			debugSecred = auth.DebugCookieKey
		}

		return []byte(debugSecred), nil
	}

	path := path.Join(env["SECRETS_PATH"], name)
	secret, err := os.ReadFile(path)
	if err != nil {
		// TODO EXTERMAL ERROR
		return nil, fmt.Errorf("reading `%s`: %w", path, err)
	}

	return secret, nil
}

func initDatastore(ctx context.Context, env map[string]string, mb datastore.Updater, errHandler func(error)) (*datastore.Datastore, func(context.Context), error) {
	maxParallel, err := strconv.Atoi(env["MAX_PARALLEL_KEYS"])
	if err != nil {
		return nil, nil, fmt.Errorf("environment variable MAX_PARALLEL_KEYS has to be a number, not %s", env["MAX_PARALLEL_KEYS"])
	}

	timeout, err := parseDuration(env["DATASTORE_TIMEOUT"])
	if err != nil {
		return nil, nil, fmt.Errorf("environment variable DATASTORE_TIMEOUT has to be a duration like 3s, not %s: %w", env["DATASTORE_TIMEOUT"], err)
	}

	datastoreSource := datastore.NewSourceDatastore(
		env["DATASTORE_READER_PROTOCOL"]+"://"+env["DATASTORE_READER_HOST"]+":"+env["DATASTORE_READER_PORT"],
		mb,
		maxParallel,
		timeout,
	)

	password, err := secret(env, "postgres_password")
	if err != nil {
		return nil, nil, fmt.Errorf("getting postgres password: %w", err)
	}

	addr := fmt.Sprintf(
		"postgres://%s@%s:%s/%s",
		env["DATASTORE_DATABASE_USER"],
		env["DATASTORE_DATABASE_HOST"],
		env["DATASTORE_DATABASE_PORT"],
		env["DATASTORE_DATABASE_NAME"],
	)

	postgresSource, err := datastore.NewSourcePostgres(ctx, addr, string(password), datastoreSource)
	if err != nil {
		return nil, nil, fmt.Errorf("creating connection to postgres: %w", err)
	}

	ds := datastore.New(
		postgresSource,
		nil,
		datastoreSource,
	)

	background := func(ctx context.Context) {
		go ds.ListenOnUpdates(ctx, errHandler)
	}

	return ds, background, nil
}

// buildAuth returns the auth service needed by the http server.
//
// This function is not blocking. The context is used to give it to auth.New
// that uses it to stop background goroutines.
func buildAuth(
	ctx context.Context,
	env map[string]string,
	messageBus auth.LogoutEventer,
	errHandler func(error),
) (authenticater, error) {
	method := env["AUTH"]
	switch method {
	case "ticket":
		fmt.Println("Auth Method: ticket")

		tokenKey, err := secret(env, "auth_token_key")
		if err != nil {
			return nil, fmt.Errorf("getting token secret: %w", err)
		}

		cookieKey, err := secret(env, "auth_cookie_key")
		if err != nil {
			return nil, fmt.Errorf("getting cookie secret: %w", err)
		}

		if string(tokenKey) == auth.DebugTokenKey || string(cookieKey) == auth.DebugCookieKey {
			fmt.Println("Auth with debug key")
		}

		protocol := env["AUTH_PROTOCOL"]
		host := env["AUTH_HOST"]
		port := env["AUTH_PORT"]
		url := protocol + "://" + host + ":" + port

		fmt.Printf("Auth Service: %s\n", url)
		a, err := auth.New(url, []byte(tokenKey), []byte(cookieKey))
		if err != nil {
			return nil, fmt.Errorf("creating auth service: %w", err)
		}
		go a.ListenOnLogouts(ctx, messageBus, errHandler)
		go a.PruneOldData(ctx)

		return a, nil

	case "fake":
		fmt.Println("Auth Method: FakeAuth (User ID 1 for all requests)")
		return authStub(1), nil

	default:
		return nil, fmt.Errorf("unknown auth method %s", method)
	}
}

// authStub implements the authenticater interface. It allways returs the given
// user id.
type authStub int

// Authenticate does nothing.
func (a authStub) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return r.Context(), nil
}

// FromContext returns the uid the object was initialiced with.
func (a authStub) FromContext(ctx context.Context) int {
	return int(a)
}

type messageBus interface {
	datastore.Updater
	auth.LogoutEventer
}

func buildMessageBus(env map[string]string) (messageBus, error) {
	redisAddress := env["MESSAGE_BUS_HOST"] + ":" + env["MESSAGE_BUS_PORT"]
	conn := messageBusRedis.NewConnection(redisAddress)
	if env["REDIS_TEST_CONN"] == "true" {
		if err := conn.TestConn(); err != nil {
			return nil, fmt.Errorf("connect to redis: %w", err)
		}
	}

	return &messageBusRedis.Redis{Conn: conn}, nil
}

func buildRedisBackend(ctx context.Context, env map[string]string) (*redis.Backend, error) {
	addr := env["VOTE_REDIS_HOST"] + ":" + env["VOTE_REDIS_PORT"]
	r := redis.New(addr)
	r.Wait(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return r, nil
}

func buildPostgresBackend(ctx context.Context, env map[string]string) (*postgres.Backend, error) {
	password, err := secret(env, "VOTE_DATABASE_PASSWORD_FILE")
	if err != nil {
		return nil, fmt.Errorf("reading postgres password: %w", err)
	}

	addr := fmt.Sprintf(
		"postgres://%s@%s:%s/%s",
		env["VOTE_DATABASE_USER"],
		env["VOTE_DATABASE_HOST"],
		env["VOTE_DATABASE_PORT"],
		env["VOTE_DATABASE_NAME"],
	)
	p, err := postgres.New(ctx, addr, string(password))
	if err != nil {
		return nil, fmt.Errorf("creating postgres connection pool: %w", err)
	}

	p.Wait(ctx)
	if err := p.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("creating shema: %w", err)
	}
	return p, nil
}

func buildBackends(ctx context.Context, env map[string]string) (fast Backend, long Backend, err error) {
	var rb *redis.Backend
	var pb *postgres.Backend

	setBackend := func(name string) (Backend, error) {
		switch name {
		case "memory":
			return memory.New(), nil

		case "redis":
			if rb == nil {
				rb, err = buildRedisBackend(ctx, env)
				if err != nil {
					return nil, fmt.Errorf("build redis backend: %w", err)
				}
			}
			return rb, nil

		case "postgres":
			if pb == nil {
				pb, err = buildPostgresBackend(ctx, env)
			}
			return pb, nil

		default:
			return nil, fmt.Errorf("unknown backend %s", name)
		}
	}

	fast, err = setBackend(env["VOTE_BACKEND_FAST"])
	if err != nil {
		return nil, nil, fmt.Errorf("setting fast backend: %w", err)
	}

	long, err = setBackend(env["VOTE_BACKEND_LONG"])
	if err != nil {
		return nil, nil, fmt.Errorf("setting long backend: %w", err)
	}

	return fast, long, nil
}

func parseDuration(s string) (time.Duration, error) {
	sec, err := strconv.Atoi(s)
	if err == nil {
		// TODO External error
		return time.Duration(sec) * time.Second, nil
	}

	return time.ParseDuration(s)
}
