package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/xerrors"
)

const defaultPort = 3489

func main() {
	time.Local = time.UTC

	port, err := parseConfig()
	if err != nil {
		abort("error: %v", err)
	}

	denyList := NewMemoryDenyList()
	store := NewMemoryBoardStore()

	server := NewServer(store, denyList, port)
	if err := server.Start(); err != nil {
		abort("error: %v", err)
	}
}

func abort(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

func parseConfig() (int, error) {
	portStr := os.Getenv("PORT")
	if portStr == "" {
		return defaultPort, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, xerrors.Errorf("err parsing port string %q: %w", portStr, err)
	}

	return port, nil
}
