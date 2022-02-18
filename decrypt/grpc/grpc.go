package grpc

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
	"google.golang.org/grpc"
)

// RunServer runs a grpc server on the given addr until ctx is done.
func RunServer(ctx context.Context, decrypt *decrypt.Decrypt, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on address %q: %w", addr, err)
	}

	registrar := grpc.NewServer()
	decryptServer := grpcServer{decrypt}

	RegisterDecryptServer(registrar, decryptServer)

	wait := make(chan struct{})
	go func() {
		<-ctx.Done()
		registrar.GracefulStop()
		wait <- struct{}{}
	}()

	log.Printf("Running grpc server on %s\n", addr)
	if err := registrar.Serve(lis); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	<-wait

	return nil
}

type grpcServer struct {
	decrypt *decrypt.Decrypt
}

func (s grpcServer) Start(ctx context.Context, req *StartRequest) (*StartResponse, error) {
	pubKey, pubKeySig, err := s.decrypt.Start(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("starting vote: %w", err)
	}

	return &StartResponse{
		PubKey: pubKey,
		PubSig: pubKeySig,
	}, nil
}

func (s grpcServer) Stop(ctx context.Context, req *StopRequest) (*StopResponse, error) {
	decrypted, signature, err := s.decrypt.Stop(ctx, req.Id, req.Votes)
	if err != nil {
		return nil, fmt.Errorf("stopping vote: %w", err)
	}

	return &StopResponse{
		Votes:     decrypted,
		Signature: signature,
	}, nil
}

func (s grpcServer) Clear(ctx context.Context, req *ClearRequest) (*ClearResponse, error) {
	err := s.decrypt.Clear(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("clearing vote: %w", err)
	}

	return new(ClearResponse), nil
}
