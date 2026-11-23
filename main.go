package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// Init nftables and bring the wlt table (including set elements from
	// state) into the desired shape before serving.
	nft := NewNFTManager(cfg, DesiredFromState(cfg, state))
	if res, err := nft.Sync(); err != nil {
		return fmt.Errorf("init nftables: %w", err)
	} else if len(res.MissingIfaces) > 0 {
		log.Printf("warn: LAN interface(s) not present yet, will attach when they appear: %v", res.MissingIfaces)
	}
	log.Printf("nftables table %q synced", cfg.TableName)

	reconciler := NewReconciler(cfg, nft)
	reconcileCtx, reconcileCancel := context.WithCancel(context.Background())
	reconcileStopped := make(chan struct{})
	go func() {
		if err := reconciler.Start(reconcileCtx); err != nil && reconcileCtx.Err() == nil {
			log.Printf("reconciler stopped: %v", err)
		}
		close(reconcileStopped)
	}()

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
		reconcileCancel()
		return err
	case sig := <-sigCh:
		log.Printf("Received signal: %v, shutting down...", sig)
	}

	reconcileCancel()

	// Wait for reconciler to finish shutdown
	select {
	case <-reconcileStopped:
	case <-time.After(5 * time.Second):
		log.Printf("Warning: reconciler did not shut down within 5s")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	if cfg.CleanupOnExit {
		log.Printf("Cleaning up nftables...")
		if err := nft.Cleanup(); err != nil {
			log.Printf("warn: nft cleanup: %v", err)
		} else {
			log.Printf("nftables cleaned up")
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
