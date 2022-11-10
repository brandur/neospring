package main

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v6"
)

const defaultPort = 3489

type Config struct {
	Port int `env:"PORT" envDefault:"3489"`
}

func main() {
	time.Local = time.UTC

	config := Config{}
	if err := env.Parse(&config); err != nil {
		abort("error parsing env config: %v", err)
	}

	denyList := NewMemoryDenyList()
	store := NewMemoryBoardStore()

	server := NewServer(store, denyList, config.Port)
	if err := server.Start(); err != nil {
		abort("error: %v", err)
	}
}

func abort(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
