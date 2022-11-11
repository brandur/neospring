package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/brandur/neospring/internal/nskeygen"
)

const defaultPort = 4434 // 2217 * 2

func main() {
	time.Local = time.UTC

	rootCmd := &cobra.Command{
		Use:   "neospring",
		Short: "Spring '83 server and tools",
		Long: strings.TrimSpace(`
Server and tooling implementations for Spring '83, which is a small scale,
independent social platform that doesn't encourage the bad feedback loops of
traditional social media.

Running with no arguments starts the server.
			`),
		Example: strings.TrimSpace(`
# start the server listening on $PORT
neospring serve

# generate a new key
neospring keygen
		`),
		Run: func(cmd *cobra.Command, args []string) {
			if err := runServe(); err != nil {
				abortErr(err)
			}
		},
	}

	// neospring keygen
	{
		cmd := &cobra.Command{
			Use:   "keygen",
			Short: "Generate a conforming Spring '83 keypair",
			Long: strings.TrimSpace(`
Boards in Spring '83 are published with an Ed25519 public key cryptography key
pair with a specific suffix that embeds a magic number and expiry month, which
builds in an automatic challenge factor in generating a new key, thereby helping
to curb abuse. This command brute forces a conforming keypair in a way that
leverages parallelism and some optimizations to do so as quickly as possible,
but depending on hardware, may still take 3 to 30 minutes to complete.
			`),
			Run: func(cmd *cobra.Command, args []string) {
				if err := runKeygen(); err != nil {
					abortErr(err)
				}
			},
		}
		rootCmd.AddCommand(cmd)
	}

	// neospring serve
	{
		cmd := &cobra.Command{
			Use:   "serve",
			Short: "Start Spring '83 server",
			Long: strings.TrimSpace(fmt.Sprintf(`
Starts a Spring '83 server, binding to $PORT, or default to %d. Allows boards to
be posted and retrieved in accordance with protocol specification.
			`, defaultPort)),
			Run: func(cmd *cobra.Command, args []string) {
				if err := runServe(); err != nil {
					abortErr(err)
				}
			},
		}
		rootCmd.AddCommand(cmd)
	}

	if err := rootCmd.Execute(); err != nil {
		abortErr(err)
	}
}

func abort(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func abortErr(err error) {
	abort("error: %v", err)
}

func runKeygen() error {
	t := time.Now()
	fmt.Printf("Brute forcing a Spring '83 key (this could take a while)\n")

	key, totalIterations, err := nskeygen.GenerateConformingKey(context.Background(), t)
	if err != nil {
		return err
	}

	fmt.Printf("Succeeded in %v with %d iterations\n", time.Since(t), totalIterations)
	fmt.Printf("Private key: %s\n", key.PrivateKey)
	fmt.Printf("Public  key: %s\n", key.PublicKey)

	return nil
}

func runServe() error {
	type Config struct {
		Port int `env:"PORT" envDefault:"4434"`
	}

	config := Config{}
	if err := env.Parse(&config); err != nil {
		return xerrors.Errorf("error parsing env config: %w", err)
	}

	denyList := NewMemoryDenyList()
	store := NewMemoryBoardStore()

	server := NewServer(store, denyList, config.Port)
	if err := server.Start(); err != nil {
		return err
	}

	return nil
}
