package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const engineCommit = "restic-ba802d42b7294c98b62c16d1157ea3e80820c019+wormhole.18"

type engine struct {
	bin        string
	stateDir   string
	parentLock bool
}

type commandError struct {
	Args   []string
	Code   int
	Output string
}

func (e *commandError) Error() string {
	return fmt.Sprintf("restic %s failed (exit %d): %s", strings.Join(e.Args, " "), e.Code, e.Output)
}

func (e engine) run(ctx context.Context, stdin io.Reader, jsonOutput bool, args ...string) ([]byte, error) {
	prefix := []string{"--cache-dir", filepath.Join(e.stateDir, "cache")}
	if e.parentLock {
		prefix = append(prefix, "--wormhole-parent-lock")
	}
	if jsonOutput {
		prefix = append(prefix, "--json")
	}
	args = append(prefix, args...)
	cmd := exec.CommandContext(ctx, e.bin, args...)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	code := 1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	message := strings.TrimSpace(stderr.String() + "\n" + stdout.String())
	if len(message) > 8000 {
		message = message[len(message)-8000:]
	}
	return nil, &commandError{Args: args, Code: code, Output: message}
}

func (e engine) acquireRepositoryLease(ctx context.Context) (context.Context, engine, func() error, error) {
	if _, err := e.run(ctx, nil, false, "unlock"); err != nil {
		return nil, e, nil, fmt.Errorf("remove stale repository locks: %w", err)
	}

	// ponytail: this repository-wide lease serializes environments; use per-environment
	// object leases if shared-repository throughput becomes necessary.
	leaseCtx, cancel := context.WithCancel(ctx)
	args := []string{"--option", "s3.connections=1", "--cache-dir", filepath.Join(e.stateDir, "cache"), "wormhole-lock"}
	cmd := exec.CommandContext(leaseCtx, e.bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, e, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, e, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, e, nil, err
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		_ = stdin.Close()
		cancel()
		waitErr := cmd.Wait()
		return nil, e, nil, fmt.Errorf("acquire repository lease: ready=%q read=%v process=%v: %s", strings.TrimSpace(line), err, waitErr, strings.TrimSpace(stderr.String()))
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		cancel()
	}()
	leased := e
	leased.parentLock = true
	release := func() error {
		closeErr := stdin.Close()
		waitErr := <-done
		cancel()
		if waitErr != nil {
			return fmt.Errorf("repository lease ended: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
		}
		return closeErr
	}
	return leaseCtx, leased, release, nil
}

func (e engine) ensureRepository(ctx context.Context) error {
	if _, err := e.run(ctx, nil, false, "cat", "config"); err == nil {
		return nil
	} else {
		var commandErr *commandError
		if !errors.As(err, &commandErr) || commandErr.Code != 10 {
			return err
		}
	}
	_, err := e.run(ctx, nil, true, "init", "--repository-version", "2")
	return err
}

func (e engine) exclusionFile(cfg Config) (string, error) {
	path := filepath.Join(e.stateDir, "exclude.patterns")
	patterns := append([]string(nil), cfg.Exclude...)
	mounts, err := mountTable()
	if err != nil {
		return "", err
	}
	for _, mount := range mounts {
		if mount.Path != "/" && transientFilesystem(mount.Filesystem) {
			if strings.ContainsAny(mount.Path, "*?[\\\r\n") {
				return "", fmt.Errorf("transient mount path cannot be represented safely: %q", mount.Path)
			}
			patterns = append(patterns, mount.Path+"/**")
		}
	}
	slices.Sort(patterns)
	patterns = slices.Compact(patterns)
	return path, os.WriteFile(path, []byte(strings.Join(patterns, "\n")+"\n"), 0600)
}

func (e engine) backup(ctx context.Context, cfg Config, parent string, force bool, tags ...string) (backupSummary, error) {
	excludes, err := e.exclusionFile(cfg)
	if err != nil {
		return backupSummary{}, err
	}
	args := []string{"backup", "--exclude-file", excludes}
	if cfg.OneFileSystem {
		args = append(args, "--one-file-system")
	}
	if parent != "" {
		args = append(args, "--parent", parent)
	}
	if force {
		args = append(args, "--force")
	}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	args = append(args, "--host", "wormhole")
	args = append(args, "--")
	args = append(args, cfg.Roots...)
	out, err := e.run(ctx, nil, true, args...)
	if err != nil {
		return backupSummary{}, err
	}
	var summary backupSummary
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var event backupSummary
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.MessageType == "summary" {
			summary = event
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, err
	}
	if summary.SnapshotID == "" {
		return summary, errors.New("restic backup completed without a snapshot ID")
	}
	return summary, nil
}

func (e engine) backupManifest(ctx context.Context, manifest Manifest) (string, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	args := []string{
		"backup", "--stdin", "--stdin-filename", "wormhole-manifest.json",
		"--tag", "wormhole-manifest",
		"--tag", "env:" + manifest.EnvironmentID,
		"--tag", "capture:" + manifest.CaptureID,
		"--host", "wormhole",
	}
	out, err := e.run(ctx, bytes.NewReader(data), true, args...)
	if err != nil {
		return "", err
	}
	var summary backupSummary
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		var event backupSummary
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.MessageType == "summary" {
			summary = event
		}
	}
	if summary.SnapshotID == "" {
		return "", errors.New("manifest backup completed without a snapshot ID")
	}
	return summary.SnapshotID, scanner.Err()
}

func (e engine) diff(ctx context.Context, from, to string, ignoreFileModTime bool) ([]Change, error) {
	args := []string{"diff", "--metadata-portable"}
	if ignoreFileModTime {
		args = append(args, "--ignore-file-mtime")
	}
	out, err := e.run(ctx, nil, true, append(args, from, to)...)
	if err != nil {
		return nil, err
	}
	changes := make([]Change, 0)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event diffEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode restic diff: %w", err)
		}
		if event.MessageType == "change" {
			changes = append(changes, Change{Path: filepath.Clean(event.Path), Modifier: event.Modifier})
		}
	}
	return changes, scanner.Err()
}

func (e engine) latestManifest(ctx context.Context, environmentID string) (Manifest, error) {
	out, err := e.run(ctx, nil, true, "snapshots", "--tag", "wormhole-manifest")
	if err != nil {
		return Manifest{}, err
	}
	var snapshots []resticSnapshot
	if err := json.Unmarshal(out, &snapshots); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest snapshots: %w", err)
	}
	tag := "env:" + environmentID
	var candidates []resticSnapshot
	for _, snapshot := range snapshots {
		if slices.Contains(snapshot.Tags, tag) {
			candidates = append(candidates, snapshot)
		}
	}
	if len(candidates) == 0 {
		return Manifest{}, fmt.Errorf("no committed capture for environment %q", environmentID)
	}
	slices.SortFunc(candidates, func(a, b resticSnapshot) int { return a.Time.Compare(b.Time) })
	return e.manifest(ctx, candidates[len(candidates)-1].ID)
}

func (e engine) manifest(ctx context.Context, snapshotID string) (Manifest, error) {
	out, err := e.run(ctx, nil, false, "dump", snapshotID, "/wormhole-manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(out, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	manifest.ManifestSnapshotID = snapshotID
	return manifest, nil
}

func (e engine) restorePaths(ctx context.Context, snapshotID string, paths []string, target string, verify bool) error {
	if len(paths) == 0 {
		return nil
	}
	list, err := os.CreateTemp(e.stateDir, "restore-paths-*.raw")
	if err != nil {
		return err
	}
	name := list.Name()
	defer os.Remove(name)
	for _, path := range paths {
		if _, err := list.Write(append([]byte(filepath.Clean(path)), 0)); err != nil {
			list.Close()
			return err
		}
	}
	if err := list.Close(); err != nil {
		return err
	}
	args := []string{"restore", snapshotID, "--target", target, "--include-file-raw", name, "--overwrite", "always", "--sparse"}
	if verify {
		args = append(args, "--verify")
	}
	_, err = e.run(ctx, nil, true, args...)
	return err
}

func loadManifest(ctx context.Context, e engine, environmentID, ref string) (Manifest, error) {
	if ref == "latest" {
		return e.latestManifest(ctx, environmentID)
	}
	return e.manifest(ctx, ref)
}
