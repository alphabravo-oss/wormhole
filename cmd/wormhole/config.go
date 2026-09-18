package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

var defaultExcludes = []string{
	"/proc/**", "/sys/**", "/dev/**", "/run/**", "/tmp/**", "/var/tmp/**",
	"/lost+found/**", "/swapfile", "/var/cache/**",
	"/var/log/*.log", "/var/log/**/*.log", "/var/log/**/*.gz", "/var/log/**/*.xz", "/var/log/**/*.old",
	"/var/log/syslog*", "/var/log/dmesg*", "/var/log/faillog", "/var/log/wtmp.db", "/var/log/sysstat/**",
	"/boot/**", "/lib/modules/**", "/usr/lib/modules/**",
	"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostname",
	"/etc/resolv.conf",
	"/etc/udev/rules.d/70-persistent-net.rules", "/etc/ssh/ssh_host_*",
	"/etc/netplan/50-cloud-init.yaml", "/etc/network/interfaces.d/50-cloud-init",
	"/etc/NetworkManager/system-connections/cloud-init-*", "/etc/systemd/network/10-cloud-init-*",
	"/etc/sysconfig/network-scripts/ifcfg-eth0",
	"/var/lib/cloud/**", "/etc/cloud/**", "/var/lib/systemd/random-seed", "/var/lib/systemd/timesync/**",
	"/var/lib/dhcp/**", "/var/lib/NetworkManager/**", "/var/lib/amazon/**", "/var/lib/google/**", "/var/lib/waagent/**", "/var/lib/hetzner/**",
	"/var/lib/ubuntu-advantage/**",
	// ponytail: Snapd state contains per-boot host identity; add structured reconciliation before supporting user-installed snaps.
	"/var/lib/dhcpcd/**", "/var/lib/landscape/**", "/var/lib/snapd/state.json",
	"/var/lib/command-not-found/**",
	"/var/lib/dnf/repos/**/countme",
	"/var/lib/chrony/**", "/var/lib/logrotate/**",
	"/var/lib/lastlog/**", "/var/lib/plymouth/boot-duration", "/var/lib/wtmpdb/**",
	"/var/spool/anacron/**",
	"/var/lib/unbound/root.key",
	"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
	"/etc/sudoers.d/90-cloud-init-users", "/etc/ssh/sshd_config.d/50-cloud-init.conf",
	"/usr/local/bin/wormhole", "/usr/local/bin/restic",
	"/etc/systemd/system/wormhole.service",
	"/etc/systemd/system/wormhole-baseline.service", "/etc/systemd/system/wormhole-capture.service", "/etc/systemd/system/wormhole-restore.service",
	"/etc/systemd/system/wormhole-baseline@.service", "/etc/systemd/system/wormhole-capture@.service", "/etc/systemd/system/wormhole-restore@.service",
	"/var/log/journal/**", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
}

var defaultProtectedServices = []string{
	"auditd.service", "chronyd.service", "dbus.service", "dbus-broker.service", "getty@.service", "serial-getty@.service", "ssh.service", "sshd.service",
	"NetworkManager.service", "networking.service", "systemd-networkd.service", "systemd-resolved.service",
	"systemd-journald.service", "systemd-logind.service", "systemd-udevd.service", "systemd-timesyncd.service",
	"dbus.socket", "ssh.socket", "sshd.socket", "sshd-unix-local.socket", "sshd-vsock.socket", "sssd.service", "sssd-kcm.socket", "systemd-journald.socket", "systemd-udevd-control.socket", "systemd-udevd-kernel.socket",
	"cloud-init.service", "cloud-config.service", "cloud-final.service", "amazon-ssm-agent.service",
	"google-guest-agent.service", "google-osconfig-agent.service", "walinuxagent.service", "waagent.service", "qemu-guest-agent.service",
	"dm-event.socket", "iscsid.service", "iscsid.socket", "lvm2-lvmpolld.socket", "multipathd.service", "multipathd.socket", "open-iscsi.service",
	"wormhole.service", "wormhole-baseline.service", "wormhole-capture.service", "wormhole-restore.service",
	"wormhole-baseline@.service", "wormhole-capture@.service", "wormhole-restore@.service",
	"user@.service", "user-runtime-dir@.service",
}

func loadConfig(path, stateDir string) (Config, error) {
	cfg := Config{
		Roots:              []string{"/"},
		Exclude:            append([]string(nil), defaultExcludes...),
		ProtectedServices:  append([]string(nil), defaultProtectedServices...),
		ReconcileFiles:     []string{"/etc/hosts"},
		OneFileSystem:      false,
		RestoreVerify:      true,
		RequireSourceFence: true,
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		var override struct {
			Roots              []string `json:"roots"`
			Exclude            []string `json:"exclude"`
			QuiesceServices    []string `json:"quiesce_services"`
			ProtectedServices  []string `json:"protected_services"`
			ReconcileFiles     []string `json:"reconcile_files"`
			OneFileSystem      *bool    `json:"one_file_system"`
			RestoreVerify      *bool    `json:"restore_verify"`
			RequireSourceFence *bool    `json:"require_source_fence"`
		}
		if err := json.Unmarshal(data, &override); err != nil {
			return cfg, fmt.Errorf("parse config: %w", err)
		}
		if len(override.Roots) > 0 {
			cfg.Roots = override.Roots
		}
		cfg.Exclude = append(cfg.Exclude, override.Exclude...)
		cfg.QuiesceServices = override.QuiesceServices
		cfg.ProtectedServices = append(cfg.ProtectedServices, override.ProtectedServices...)
		cfg.ReconcileFiles = append(cfg.ReconcileFiles, override.ReconcileFiles...)
		if override.OneFileSystem != nil {
			cfg.OneFileSystem = *override.OneFileSystem
		}
		if override.RestoreVerify != nil {
			cfg.RestoreVerify = *override.RestoreVerify
		}
		if override.RequireSourceFence != nil {
			cfg.RequireSourceFence = *override.RequireSourceFence
		}
	}
	cfg.ReconcileFiles = append(cfg.ReconcileFiles, discoverExistingTextFiles("/etc/fstab", "/etc/crypttab")...)
	cfg.ReconcileFiles = append(cfg.ReconcileFiles, discoverAuthorizedKeys()...)
	stateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return cfg, err
	}
	cfg.Exclude = append(cfg.Exclude, filepath.ToSlash(stateDir), filepath.ToSlash(stateDir)+"/**")
	for i, path := range cfg.ReconcileFiles {
		path, err = filepath.Abs(path)
		if err != nil {
			return cfg, err
		}
		cfg.ReconcileFiles[i] = filepath.Clean(path)
		cfg.Exclude = append(cfg.Exclude, cfg.ReconcileFiles[i])
	}
	for i, root := range cfg.Roots {
		root, err = filepath.Abs(root)
		if err != nil {
			return cfg, err
		}
		if root == "/proc" || root == "/sys" || root == "/dev" || root == "/run" {
			return cfg, fmt.Errorf("runtime filesystem %s cannot be a managed root", root)
		}
		cfg.Roots[i] = filepath.Clean(root)
	}
	for _, path := range cfg.ReconcileFiles {
		if !withinRoots(path, cfg.Roots) {
			return cfg, fmt.Errorf("reconciled file %s is outside managed roots", path)
		}
		if path != "/etc/hosts" && isProtectedPath(path) {
			return cfg, fmt.Errorf("reconciled file %s is protected host state", path)
		}
	}
	for i := range cfg.Exclude {
		cfg.Exclude[i] = filepath.ToSlash(strings.TrimSpace(cfg.Exclude[i]))
	}
	for _, pattern := range append([]string(nil), cfg.Exclude...) {
		if strings.HasSuffix(pattern, "/**") {
			cfg.Exclude = append(cfg.Exclude, strings.TrimSuffix(pattern, "/**"))
		}
	}
	slices.Sort(cfg.Roots)
	cfg.Roots = slices.Compact(cfg.Roots)
	slices.Sort(cfg.Exclude)
	cfg.Exclude = slices.Compact(cfg.Exclude)
	slices.Sort(cfg.QuiesceServices)
	cfg.QuiesceServices = slices.Compact(cfg.QuiesceServices)
	slices.Sort(cfg.ProtectedServices)
	cfg.ProtectedServices = slices.Compact(cfg.ProtectedServices)
	slices.Sort(cfg.ReconcileFiles)
	cfg.ReconcileFiles = slices.Compact(cfg.ReconcileFiles)
	return cfg, nil
}

func discoverExistingTextFiles(paths ...string) []string {
	result := []string{}
	for _, path := range paths {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			result = append(result, path)
		}
	}
	return result
}

func discoverAuthorizedKeys() []string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	paths := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 6 || fields[5] == "" {
			continue
		}
		path := filepath.Join(fields[5], ".ssh", "authorized_keys")
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			paths = append(paths, path)
		}
	}
	return paths
}

func extendReconcileFiles(cfg Config, paths []string) (Config, error) {
	for _, path := range paths {
		path, err := filepath.Abs(path)
		if err != nil {
			return cfg, err
		}
		path = filepath.Clean(path)
		if !withinRoots(path, cfg.Roots) || (path != "/etc/hosts" && isProtectedPath(path)) {
			return cfg, fmt.Errorf("reconciled file %s is outside the managed policy", path)
		}
		cfg.ReconcileFiles = append(cfg.ReconcileFiles, path)
		cfg.Exclude = append(cfg.Exclude, filepath.ToSlash(path))
	}
	slices.Sort(cfg.ReconcileFiles)
	cfg.ReconcileFiles = slices.Compact(cfg.ReconcileFiles)
	slices.Sort(cfg.Exclude)
	cfg.Exclude = slices.Compact(cfg.Exclude)
	return cfg, nil
}

func configHash(cfg Config) string {
	data, _ := json.Marshal(cfg)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func acquireOperationLock(stateDir string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(stateDir, "operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another Wormhole operation is already running on this VM")
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func validateRepositoryEnvironment() error {
	if os.Getenv("RESTIC_REPOSITORY") == "" && os.Getenv("RESTIC_REPOSITORY_FILE") == "" {
		return errors.New("RESTIC_REPOSITORY or RESTIC_REPOSITORY_FILE is required")
	}
	if os.Getenv("RESTIC_PASSWORD") == "" && os.Getenv("RESTIC_PASSWORD_FILE") == "" && os.Getenv("RESTIC_PASSWORD_COMMAND") == "" {
		return errors.New("RESTIC_PASSWORD, RESTIC_PASSWORD_FILE, or RESTIC_PASSWORD_COMMAND is required")
	}
	return nil
}

func validateEnvironmentID(value string) error {
	if value == "" || len(value) > 128 {
		return errors.New("environment ID must contain 1-128 letters, digits, dots, underscores, or hyphens")
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return errors.New("environment ID must contain 1-128 letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

func ensureStateDir(path string) error {
	if err := os.MkdirAll(filepath.Join(path, "jobs"), 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wormhole-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
