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

// Client holds the connection to a server
type Client struct {
	decryptClient DecryptClient
}

// NewClient creates a connection to a decrypt grpc server and wrapps then
// into a decrypt.crypto interface.
func NewClient(addr string) (*Client, error) {
	// TODO: use secure connection
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("creating connection to decrypt service: %w", err)
	}

	// TODO: Close conn

	decrypter := NewDecryptClient(conn)
	return &Client{decryptClient: decrypter}, nil
}

// Start calls the Start grpc message.
func (c *Client) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	resp, err := c.decryptClient.Start(ctx, &StartRequest{Id: pollID})
	if err != nil {
		return nil, nil, fmt.Errorf("sending grpc message: %w", err)
	}

	return resp.PubKey, resp.PubSig, nil
}

// Stop calls the Stop grpc message.
func (c *Client) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	resp, err := c.decryptClient.Stop(ctx, &StopRequest{Id: pollID, Votes: voteList})
	if err != nil {
		return nil, nil, fmt.Errorf("sending grpc message: %w", err)
	}
	return resp.Votes, resp.Signature, nil
}

// Clear calls the Clear grpc message.
func (c *Client) Clear(ctx context.Context, pollID string) error {
	_, err := c.decryptClient.Clear(ctx, &ClearRequest{Id: pollID})
	if err != nil {
		return fmt.Errorf("sending grpc message: %w", err)
	}

	return nil
}

// TODO: wrap all errors so not information is leaked.
type grpcServer struct {
	decrypt *decrypt.Decrypt
}

func (s grpcServer) Start(ctx context.Context, req *StartRequest) (*StartResponse, error) {
	log.Println("Start request")
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
	log.Println("Stop request")
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
	log.Println("Clear request")
	err := s.decrypt.Clear(ctx, req.Id)
	if err != nil {
		return nil, fmt.Errorf("clearing vote: %w", err)
	}

	return new(ClearResponse), nil
}
