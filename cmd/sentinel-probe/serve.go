package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rootstuff/sentinel-probe/internal/control"
	"github.com/rootstuff/sentinel-probe/internal/runner"
)

// Flags fall back to SENTINEL_PROBE_* environment variables, which is how
// the systemd unit configures a node (EnvironmentFile=/etc/sentinel-probe/env).
func envOr(key, def string) string {
	if v := os.Getenv("SENTINEL_PROBE_" + key); v != "" {
		return v
	}
	return def
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	url := fs.String("url", envOr("URL", "https://sentinel.rootstuff.io"), "control plane base URL")
	region := fs.String("region", envOr("REGION", ""), "region key this node checks for")
	tokenFile := fs.String("token-file", envOr("TOKEN_FILE", "/etc/sentinel-probe/token"), "file holding the node token")
	dataDir := fs.String("data-dir", envOr("DATA_DIR", "/var/lib/sentinel-probe"), "manifest cache and result spool")
	concurrency := fs.Int("concurrency", 500, "checks in flight at once")
	syncEvery := fs.Duration("sync-interval", time.Minute, "manifest sync interval")
	debug := fs.Bool("debug", false, "log every tick")
	fs.Parse(args)

	if *region == "" {
		fmt.Fprintln(os.Stderr, "serve: -region (or SENTINEL_PROBE_REGION) is required")
		os.Exit(2)
	}
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve: cannot read token:", err)
		os.Exit(2)
	}
	token := strings.TrimSpace(string(tokenBytes))

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	r, err := runner.New(runner.Config{
		Region:       *region,
		Version:      version,
		DataDir:      *dataDir,
		Concurrency:  *concurrency,
		SyncInterval: *syncEvery,
		Log:          log,
		AlignTicks:   true,
	}, control.New(*url, token, version))
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("sentinel-probe starting", "version", version, "region", *region, "control", *url, "data", *dataDir)
	if err := r.Run(ctx); err != nil {
		log.Error("shutdown with error", "error", err)
		os.Exit(1)
	}
	log.Info("sentinel-probe stopped")
}
