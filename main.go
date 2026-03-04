package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "embed"
)

//go:embed web/index.html
var indexHTML []byte

func checkCapNetAdmin() error {
	// Try opening /proc/net/nf_conntrack which requires CAP_NET_ADMIN
	// A simpler check: see if we can open a netlink socket
	// We just check effective UID for simplicity; nft.go will fail explicitly if lacking caps
	if os.Getuid() != 0 {
		// Check if we have cap_net_admin via /proc/self/status
		// For simplicity, just warn - the real check happens when nftables fails
		return fmt.Errorf("not running as root; CAP_NET_ADMIN is required for nftables management")
	}
	return nil
}

func run() error {
	configPath := flag.String("config", "/etc/wlt/config.json", "path to config file")
	flag.Parse()

	// Check capabilities
	if err := checkCapNetAdmin(); err != nil {
		return fmt.Errorf("capability check: %w", err)
	}

	// Load config
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log.Printf("Config loaded: listen=%s table=%s chain=%s", cfg.Listen, cfg.TableName, cfg.ChainName)

	// Load state
	state, err := LoadState(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	log.Printf("State loaded: %d devices", len(state.Devices))

	// Init nftables
	nft, err := NewNFTManager(cfg)
	if err != nil {
		return fmt.Errorf("init nftables: %w", err)
	}
	log.Printf("NFTManager initialized")

	// Rebuild sets from persisted state
	if err := nft.RebuildFromState(state); err != nil {
		log.Printf("warn: rebuild from state: %v", err)
	} else {
		log.Printf("NFT sets rebuilt from state")
	}

	// Start HTTP server
	srv := NewServer(cfg, state, nft)
	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("HTTP server listening on %s", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		log.Printf("Received signal: %v, shutting down...", sig)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	if cfg.CleanupOnExit {
		log.Printf("Cleaning up nft sets...")
		if err := nft.Cleanup(); err != nil {
			log.Printf("warn: nft cleanup: %v", err)
		} else {
			log.Printf("NFT sets flushed")
		}
	}

	// Save final state
	if err := state.Save(cfg.StatePath); err != nil {
		log.Printf("warn: save state on exit: %v", err)
	}

	log.Printf("Shutdown complete")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
