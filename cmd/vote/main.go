package main

import (
	"context"
	golog "log"
	"os"
	"os/signal"
	"strconv"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
	"github.com/OpenSlides/openslides-vote-service/internal/vote"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel := interruptContext()
	defer cancel()

	log.SetInfoLogger(golog.Default())
	if dev, _ := strconv.ParseBool(os.Getenv("OPENSLIDES_DEVELOPMENT")); dev {
		log.SetDebugLogger(golog.New(os.Stderr, "DEBUG ", golog.LstdFlags))
	}

	if err := vote.Run(ctx, os.Environ()); err != nil {
		log.Info("Error: %v", err)
		os.Exit(1)
	}
}

// interruptContext works like signal.NotifyContext
//
// In only listens on os.Interrupt. If the signal is received two times,
// os.Exit(1) is called.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, unix.SIGTERM)
		<-sigint
		cancel()

		// If the signal was send for the second time, make a hard cut.
		<-sigint
		os.Exit(1)
	}()
	return ctx, cancel
}
