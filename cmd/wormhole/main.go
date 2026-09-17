package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const version = "0.1.0-dev"

type commonFlags struct {
	stateDir    string
	configPath  string
	resticBin   string
	environment string
}

func addCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.stateDir, "state-dir", envOr("WORMHOLE_STATE_DIR", "/var/lib/wormhole"), "local Wormhole state directory")
	fs.StringVar(&c.configPath, "config", os.Getenv("WORMHOLE_CONFIG"), "optional JSON configuration")
	fs.StringVar(&c.resticBin, "restic-bin", envOr("WORMHOLE_RESTIC_BIN", siblingBinary("restic")), "pinned Restic executable")
	fs.StringVar(&c.environment, "environment-id", os.Getenv("WORMHOLE_ENVIRONMENT_ID"), "stable lab environment ID")
	return c
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"status": "failed", "error": err.Error()})
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Println(version)
		return nil
	case "baseline":
		if len(args) < 2 || args[1] != "create" {
			return usageError()
		}
		fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
		common := addCommon(fs)
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if common.environment == "" {
			return errors.New("--environment-id or WORMHOLE_ENVIRONMENT_ID is required")
		}
		return createBaseline(ctx, *common)
	case "inventory":
		fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
		common := addCommon(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return inventory(ctx, *common)
	case "capture":
		if len(args) < 2 || args[1] != "run" {
			return usageError()
		}
		fs := flag.NewFlagSet("capture run", flag.ContinueOnError)
		common := addCommon(fs)
		leaveStopped := fs.Bool("leave-stopped", false, "leave quiesced workloads stopped after capture")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return capture(ctx, *common, *leaveStopped)
	case "restore":
		if len(args) < 2 || args[1] != "apply" {
			return usageError()
		}
		fs := flag.NewFlagSet("restore apply", flag.ContinueOnError)
		common := addCommon(fs)
		manifest := fs.String("manifest", "latest", "manifest snapshot ID or latest")
		sourceFenced := fs.Bool("source-fenced", false, "confirm the source VM cannot still serve the lab")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if common.environment == "" {
			return errors.New("--environment-id or WORMHOLE_ENVIRONMENT_ID is required")
		}
		return restore(ctx, *common, *manifest, *sourceFenced)
	case "inspect":
		fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
		common := addCommon(fs)
		manifest := fs.String("manifest", "latest", "manifest snapshot ID or latest")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return inspectManifest(ctx, *common, *manifest)
	case "status":
		fs := flag.NewFlagSet("status", flag.ContinueOnError)
		stateDir := fs.String("state-dir", envOr("WORMHOLE_STATE_DIR", "/var/lib/wormhole"), "local Wormhole state directory")
		jobID := fs.String("job", "", "specific job ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return showStatus(*stateDir, *jobID)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: wormhole inventory | baseline create | capture run | restore apply --source-fenced | inspect | status | version")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func siblingBinary(name string) string {
	exe, err := os.Executable()
	if err == nil {
		path := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return name
}
