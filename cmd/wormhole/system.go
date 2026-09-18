package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

var accountPaths = []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"}
var firewallCounters = regexp.MustCompile(`\[[0-9]+:[0-9]+\]`)
var nftConnectionStates = regexp.MustCompile(`\bct state ([a-z]+(?:,[a-z]+)+)`)
var kernelModuleName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

type mountInfo struct {
	Path       string
	Filesystem string
}

func transientFilesystem(name string) bool {
	switch name {
	case "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "overlay", "proc", "pstore", "ramfs", "rpc_pipefs", "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs":
		return true
	}
	return false
}

func systemInfo() (SystemInfo, error) {
	values := map[string]string{}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return SystemInfo{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"")
		}
	}
	kernel, err := commandOutput(context.Background(), "uname", "-r")
	if err != nil {
		return SystemInfo{}, err
	}
	cgroup := "v1"
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		cgroup = "v2"
	}
	manager, err := detectPackageManager()
	if err != nil {
		return SystemInfo{}, err
	}
	return SystemInfo{OSID: values["ID"], OSVersion: values["VERSION_ID"], Architecture: runtime.GOARCH, Kernel: kernel, CgroupVersion: cgroup, PackageManager: manager}, nil
}

func compatibleSystem(baseline, target SystemInfo) error {
	if baseline.OSID != target.OSID || baseline.OSVersion != target.OSVersion {
		return fmt.Errorf("os_release_mismatch: captured %s %s, target %s %s", baseline.OSID, baseline.OSVersion, target.OSID, target.OSVersion)
	}
	if baseline.Architecture != target.Architecture {
		return fmt.Errorf("architecture_mismatch: captured %s, target %s", baseline.Architecture, target.Architecture)
	}
	if baseline.Kernel != target.Kernel {
		return fmt.Errorf("kernel_mismatch: captured %s, target %s", baseline.Kernel, target.Kernel)
	}
	if baseline.CgroupVersion != target.CgroupVersion {
		return fmt.Errorf("cgroup_mismatch: captured %s, target %s", baseline.CgroupVersion, target.CgroupVersion)
	}
	if baseline.PackageManager != target.PackageManager {
		return fmt.Errorf("package_manager_mismatch: captured %s, target %s", baseline.PackageManager, target.PackageManager)
	}
	return nil
}

func kernelModuleInventory() ([]string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	modules := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !kernelModuleName.MatchString(fields[0]) {
			return nil, fmt.Errorf("invalid_kernel_module_name: %q", fields[0])
		}
		modules = append(modules, fields[0])
	}
	slices.Sort(modules)
	return slices.Compact(modules), nil
}

func kernelModuleAdditions(before, after []string) ([]string, error) {
	baseline := map[string]bool{}
	current := map[string]bool{}
	for _, name := range before {
		baseline[name] = true
	}
	for _, name := range after {
		current[name] = true
	}
	added := []string{}
	for name := range current {
		if !baseline[name] {
			added = append(added, name)
		}
	}
	slices.Sort(added)
	return added, nil
}

func validateKernelModuleAdditions(ctx context.Context, additions, current []string) error {
	loaded := map[string]bool{}
	for _, name := range current {
		loaded[name] = true
	}
	for _, name := range additions {
		if !kernelModuleName.MatchString(name) {
			return fmt.Errorf("invalid_kernel_module_name: %q", name)
		}
		if loaded[name] {
			continue
		}
		if _, err := commandOutput(ctx, "modprobe", "--dry-run", name); err != nil {
			return fmt.Errorf("kernel_module_unavailable: %s: %w", name, err)
		}
	}
	return nil
}

func applyKernelModuleAdditions(ctx context.Context, additions []string) ([]string, error) {
	current, err := kernelModuleInventory()
	if err != nil {
		return nil, err
	}
	loaded := map[string]bool{}
	for _, name := range current {
		loaded[name] = true
	}
	added := []string{}
	for _, name := range additions {
		if loaded[name] {
			continue
		}
		if _, err := commandOutput(ctx, "modprobe", name); err != nil {
			return nil, errors.Join(err, unloadKernelModules(added))
		}
		added = append(added, name)
	}
	return added, nil
}

func unloadKernelModules(modules []string) error {
	var result error
	for i := len(modules) - 1; i >= 0; i-- {
		_, err := commandOutput(context.Background(), "modprobe", "--remove", modules[i])
		result = errors.Join(result, err)
	}
	return result
}

func verifyKernelModuleAdditions(additions []string) error {
	current, err := kernelModuleInventory()
	if err != nil {
		return err
	}
	loaded := map[string]bool{}
	for _, name := range current {
		loaded[name] = true
	}
	for _, name := range additions {
		if !loaded[name] {
			return fmt.Errorf("kernel_module_restore_mismatch: %s", name)
		}
	}
	return nil
}

func firewallState(ctx context.Context) (FirewallState, error) {
	if _, err := exec.LookPath("nft"); err == nil {
		rules, err := commandOutput(ctx, "nft", "--stateless", "list", "ruleset")
		if err != nil {
			return FirewallState{}, err
		}
		return FirewallState{Backend: "nft", Rules: normalizeNFTRules(rules)}, nil
	}
	if _, err := exec.LookPath("iptables-save"); err == nil {
		rules, err := commandOutput(ctx, "iptables-save")
		if err != nil {
			return FirewallState{}, err
		}
		state := FirewallState{Backend: "iptables", Rules: normalizeFirewallCounters(rules)}
		if _, err := exec.LookPath("ip6tables-save"); err == nil {
			rules, err = commandOutput(ctx, "ip6tables-save")
			if err != nil {
				return FirewallState{}, err
			}
			state.RulesV6 = normalizeFirewallCounters(rules)
		}
		return state, nil
	}
	return FirewallState{Backend: "none"}, nil
}

func normalizeFirewallCounters(rules string) string {
	return strings.TrimSpace(firewallCounters.ReplaceAllString(rules, "[0:0]"))
}

func normalizeNFTRules(rules string) string {
	return strings.TrimSpace(nftConnectionStates.ReplaceAllStringFunc(rules, func(match string) string {
		prefix, states, _ := strings.Cut(match, " ")
		_, states, _ = strings.Cut(states, " ")
		values := strings.Split(states, ",")
		slices.Sort(values)
		return prefix + " state " + strings.Join(values, ",")
	}))
}

func applyFirewallState(ctx context.Context, state FirewallState) error {
	switch state.Backend {
	case "none":
		return nil
	case "nft":
		return commandInput(ctx, "flush ruleset\n"+state.Rules+"\n", "nft", "-f", "-")
	case "iptables":
		if err := commandInput(ctx, state.Rules+"\n", "iptables-restore"); err != nil {
			return err
		}
		if state.RulesV6 != "" {
			if err := commandInput(ctx, state.RulesV6+"\n", "ip6tables-restore"); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported_firewall_backend: %s", state.Backend)
	}
}

func securityState(ctx context.Context) (SecurityState, error) {
	if _, err := exec.LookPath("getenforce"); err != nil {
		return SecurityState{}, nil
	}
	mode, err := commandOutput(ctx, "getenforce")
	if err != nil {
		return SecurityState{}, err
	}
	switch mode {
	case "Enforcing", "Permissive", "Disabled":
		return SecurityState{SELinux: mode}, nil
	default:
		return SecurityState{}, fmt.Errorf("unknown_selinux_mode: %s", mode)
	}
}

func validateSecurityChange(baseline, captured SecurityState) error {
	if baseline == captured {
		return nil
	}
	if baseline.SELinux == "" || captured.SELinux == "" || baseline.SELinux == "Disabled" || captured.SELinux == "Disabled" {
		return fmt.Errorf("unsupported_selinux_transition: %q -> %q", baseline.SELinux, captured.SELinux)
	}
	return nil
}

func validateTargetSecurity(baseline, captured, target SecurityState) error {
	if err := validateSecurityChange(baseline, captured); err != nil {
		return err
	}
	if target != baseline && target != captured {
		return fmt.Errorf("target_security_baseline_mismatch: expected %#v or %#v, got %#v", baseline, captured, target)
	}
	if baseline != captured && target != captured {
		if _, err := exec.LookPath("setenforce"); err != nil {
			return fmt.Errorf("setenforce is required to restore SELinux runtime state: %w", err)
		}
	}
	return nil
}

func applySecurityState(ctx context.Context, state SecurityState) error {
	switch state.SELinux {
	case "":
		return nil
	case "Enforcing":
		_, err := commandOutput(ctx, "setenforce", "1")
		return err
	case "Permissive":
		_, err := commandOutput(ctx, "setenforce", "0")
		return err
	default:
		return fmt.Errorf("unsupported_selinux_mode: %s", state.SELinux)
	}
}

func sysctlInventory(ctx context.Context) (map[string]string, error) {
	values := map[string]string{}
	err := filepath.WalkDir("/proc/sys", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil // proc entries can disappear while walking
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 == 0 {
			return nil
		}
		rel, err := filepath.Rel("/proc/sys", path)
		if err != nil || !portableSysctl(rel) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 64*1024 {
			return nil
		}
		values[filepath.ToSlash(rel)] = strings.TrimSpace(string(data))
		return nil
	})
	return values, err
}

func portableSysctl(name string) bool {
	name = filepath.ToSlash(name)
	if name == "kernel/hostname" || name == "kernel/domainname" || name == "kernel/ns_last_pid" ||
		name == "kernel/threads-max" || name == "net/ipv4/tcp_fastopen_key" ||
		name == "net/ipv4/tcp_mem" || name == "net/ipv4/tcp_rmem" || name == "net/ipv4/tcp_wmem" || name == "net/ipv4/udp_mem" ||
		name == "vm/admin_reserve_kbytes" || name == "vm/user_reserve_kbytes" {
		return false
	}
	if strings.HasPrefix(name, "kernel/sched_domain/") || strings.HasPrefix(name, "user/max_") && strings.HasSuffix(name, "_namespaces") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) >= 5 && parts[0] == "net" && (parts[2] == "conf" || parts[2] == "neigh") {
		return parts[3] == "all" || parts[3] == "default"
	}
	return true
}

func sysctlChanges(before, after map[string]string) []SysctlChange {
	changes := []SysctlChange{}
	for name, old := range before {
		if current, exists := after[name]; exists && current != old {
			changes = append(changes, SysctlChange{Name: name, Before: old, After: current})
		}
	}
	slices.SortFunc(changes, func(a, b SysctlChange) int { return strings.Compare(a.Name, b.Name) })
	return changes
}

func validateSysctlChanges(changes []SysctlChange, current map[string]string) error {
	for _, change := range changes {
		if _, exists := current[change.Name]; !exists {
			return fmt.Errorf("sysctl_missing: %s", change.Name)
		}
	}
	return nil
}

func applySysctlChanges(ctx context.Context, changes []SysctlChange) (map[string]string, error) {
	current, err := sysctlInventory(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateSysctlChanges(changes, current); err != nil {
		return nil, err
	}
	rollback := map[string]string{}
	for _, change := range changes {
		rollback[change.Name] = current[change.Name]
		if current[change.Name] == change.After {
			continue
		}
		if err := writeSysctl(change.Name, change.After); err != nil {
			_ = restoreSysctls(rollback)
			return nil, err
		}
	}
	return rollback, nil
}

func restoreSysctls(values map[string]string) error {
	for name, value := range values {
		if err := writeSysctl(name, value); err != nil {
			return err
		}
	}
	return nil
}

func writeSysctl(name, value string) error {
	if !portableSysctl(name) || name != filepath.ToSlash(filepath.Clean(name)) || strings.HasPrefix(name, "../") {
		return fmt.Errorf("unsafe_sysctl_name: %s", name)
	}
	path := filepath.Join("/proc/sys", filepath.FromSlash(name))
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("set sysctl %s: %w", name, err)
	}
	_, writeErr := file.WriteString(value)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("set sysctl %s: %w", name, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("set sysctl %s: %w", name, closeErr)
	}
	return nil
}

func verifySysctlChanges(ctx context.Context, changes []SysctlChange) error {
	current, err := sysctlInventory(ctx)
	if err != nil {
		return err
	}
	for _, change := range changes {
		if current[change.Name] != change.After {
			return fmt.Errorf("sysctl_restore_mismatch: %s", change.Name)
		}
	}
	return nil
}

func storageRequirements(changes []Change) ([]StorageRequirement, error) {
	mounts, err := mountTable()
	if err != nil {
		return nil, err
	}
	requirements := map[string]StorageRequirement{}
	type fileID struct{ device, inode uint64 }
	seen := map[fileID]bool{}
	for _, change := range changes {
		if strings.Contains(change.Modifier, "-") {
			continue
		}
		info, err := os.Lstat(change.Path)
		if err != nil {
			return nil, fmt.Errorf("measure changed path %s: %w", change.Path, err)
		}
		mount, ok := persistentMountForPath(change.Path, mounts)
		if !ok {
			return nil, fmt.Errorf("no mount found for changed path %s", change.Path)
		}
		requirement := requirements[mount.Path]
		requirement.MountPoint, requirement.Filesystem = mount.Path, mount.Filesystem
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("stat metadata unavailable for %s", change.Path)
		}
		id := fileID{uint64(stat.Dev), stat.Ino}
		if !seen[id] {
			seen[id] = true
			requirement.Inodes++
			if info.Mode().IsRegular() {
				requirement.Bytes += uint64(stat.Blocks) * 512
			}
		}
		requirements[mount.Path] = requirement
	}
	result := make([]StorageRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		// Allow room for filesystem metadata and Restic's temporary writes.
		requirement.Bytes += requirement.Bytes/10 + 64*1024*1024
		requirement.Inodes += 1024
		result = append(result, requirement)
	}
	slices.SortFunc(result, func(a, b StorageRequirement) int { return strings.Compare(a.MountPoint, b.MountPoint) })
	return result, nil
}

func checkStorageRequirements(requirements []StorageRequirement) error {
	mounts, err := mountTable()
	if err != nil {
		return err
	}
	byPath := map[string]mountInfo{}
	for _, mount := range mounts {
		byPath[mount.Path] = mount
	}
	for _, requirement := range requirements {
		mount, exists := byPath[requirement.MountPoint]
		if !exists {
			return fmt.Errorf("required_mount_missing: %s", requirement.MountPoint)
		}
		if mount.Filesystem != requirement.Filesystem {
			return fmt.Errorf("mount_filesystem_mismatch: %s captured %s, target %s", requirement.MountPoint, requirement.Filesystem, mount.Filesystem)
		}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(requirement.MountPoint, &stat); err != nil {
			return err
		}
		availableBytes := stat.Bavail * uint64(stat.Bsize)
		if availableBytes < requirement.Bytes {
			return fmt.Errorf("insufficient_space: %s needs %d bytes, has %d", requirement.MountPoint, requirement.Bytes, availableBytes)
		}
		if stat.Ffree != 0 && stat.Ffree < requirement.Inodes {
			return fmt.Errorf("insufficient_inodes: %s needs %d, has %d", requirement.MountPoint, requirement.Inodes, stat.Ffree)
		}
	}
	return nil
}

func mountTable() ([]mountInfo, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	mounts := []mountInfo{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		separator := slices.Index(fields, "-")
		if len(fields) < 6 || separator < 0 || separator+1 >= len(fields) {
			return nil, fmt.Errorf("invalid mountinfo line %q", line)
		}
		mounts = append(mounts, mountInfo{Path: unescapeMountPath(fields[4]), Filesystem: fields[separator+1]})
	}
	return mounts, nil
}

func unescapeMountPath(path string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(path)
}

func mountForPath(path string, mounts []mountInfo) (mountInfo, bool) {
	path = filepath.Clean(path)
	var selected mountInfo
	found := false
	for _, mount := range mounts {
		rel, err := filepath.Rel(mount.Path, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if !found || len(mount.Path) > len(selected.Path) {
			selected, found = mount, true
		}
	}
	return selected, found
}

func persistentMountForPath(path string, mounts []mountInfo) (mountInfo, bool) {
	persistent := make([]mountInfo, 0, len(mounts))
	for _, mount := range mounts {
		if !transientFilesystem(mount.Filesystem) {
			persistent = append(persistent, mount)
		}
	}
	return mountForPath(path, persistent)
}

func hostIdentity(ctx context.Context) (HostIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return HostIdentity{}, err
	}
	machineID, _ := os.ReadFile("/etc/machine-id")
	keys, _ := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	slices.Sort(keys)
	h := sha256.New()
	for _, path := range keys {
		data, err := os.ReadFile(path)
		if err == nil {
			h.Write([]byte(path))
			h.Write(data)
		}
	}
	addresses := []string{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, address := range addrs {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				addresses = append(addresses, address.String())
			}
		}
	}
	slices.Sort(addresses)
	routes, _ := commandOutput(ctx, "ip", "route", "show", "default")
	routeHash := sha256.Sum256([]byte(routes))
	return HostIdentity{
		Hostname: hostname, MachineID: strings.TrimSpace(string(machineID)),
		SSHHostKeys: hex.EncodeToString(h.Sum(nil)), Addresses: addresses,
		DefaultRoutes: hex.EncodeToString(routeHash[:]),
	}, nil
}

func sameHostIdentity(before, after HostIdentity) error {
	if before.Hostname != after.Hostname || before.MachineID != after.MachineID || before.SSHHostKeys != after.SSHHostKeys || before.DefaultRoutes != after.DefaultRoutes {
		return errors.New("protected_host_identity_changed")
	}
	for _, address := range before.Addresses {
		if !slices.Contains(after.Addresses, address) {
			return fmt.Errorf("protected_host_address_disappeared: %s", address)
		}
	}
	return nil
}

func serviceIntents(ctx context.Context) (map[string]ServiceIntent, error) {
	const workloadUnitTypes = "service,socket,timer,path,mount,automount"
	out, err := commandOutput(ctx, "systemctl", "list-unit-files", "--type="+workloadUnitTypes, "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, fmt.Errorf("systemd is required: %w", err)
	}
	services := map[string]ServiceIntent{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			services[fields[0]] = ServiceIntent{UnitFileState: fields[1], ActiveState: "inactive"}
		}
	}
	out, err = commandOutput(ctx, "systemctl", "list-units", "--type="+workloadUnitTypes+",scope", "--all", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			intent := services[fields[0]]
			intent.ActiveState = stableActiveState(fields[2])
			intent.SubState = fields[3]
			services[fields[0]] = intent
		}
	}
	return services, nil
}

func workloadServiceIntents(current, baseline map[string]ServiceIntent, cfg Config) map[string]ServiceIntent {
	selected := map[string]ServiceIntent{}
	for name, intent := range current {
		if strings.HasSuffix(name, ".scope") || (isProtectedService(name, cfg.ProtectedServices) && !slices.Contains(cfg.QuiesceServices, name)) {
			continue
		}
		if previous, existed := baseline[name]; existed && sameServiceIntent(previous, intent) {
			continue
		}
		if isMountUnit(name) {
			if intent.UnitFileState == "" {
				continue
			}
			if _, existedAtBaseline := baseline[name]; existedAtBaseline {
				continue
			}
		}
		selected[name] = intent
	}
	return selected
}

func stableActiveState(state string) string {
	if state == "active" || state == "activating" || state == "reloading" {
		return "active"
	}
	return "inactive"
}

func sameServiceIntent(a, b ServiceIntent) bool {
	return a.UnitFileState == b.UnitFileState && stableActiveState(a.ActiveState) == stableActiveState(b.ActiveState)
}

func isMountUnit(name string) bool {
	return strings.HasSuffix(name, ".mount") || strings.HasSuffix(name, ".automount")
}

func isProtectedService(name string, protected []string) bool {
	if strings.HasPrefix(name, "systemd-") {
		return true
	}
	for _, item := range protected {
		if name == item {
			return true
		}
		if strings.Contains(item, "@.") {
			prefix, suffix, _ := strings.Cut(item, "@.")
			if strings.HasPrefix(name, prefix+"@") && strings.HasSuffix(name, "."+suffix) {
				return true
			}
		}
	}
	return false
}

func quiesceServices(ctx context.Context, current map[string]ServiceIntent, cfg Config) ([]string, error) {
	stopped := []string{}
	for name, intent := range current {
		activeWriter := intent.ActiveState == "active" && intent.SubState != "exited" && intent.SubState != "dead"
		if !activeWriter || isMountUnit(name) || (isProtectedService(name, cfg.ProtectedServices) && !slices.Contains(cfg.QuiesceServices, name)) {
			continue
		}
		if strings.HasSuffix(name, ".scope") {
			if name == "init.scope" {
				continue
			}
			cgroup, err := commandOutput(ctx, "systemctl", "show", "--property=ControlGroup", "--value", name)
			if err != nil {
				return nil, err
			}
			if cgroup == "/user.slice" || strings.HasPrefix(cgroup, "/user.slice/") {
				continue
			}
		}
		stopped = append(stopped, name)
	}
	slices.Sort(stopped)
	if len(stopped) == 0 {
		return stopped, nil
	}
	args := append([]string{"stop", "--"}, stopped...)
	if _, err := commandOutput(ctx, "systemctl", args...); err != nil {
		_ = resumeServices(context.Background(), stopped)
		return nil, fmt.Errorf("quiesce services: %w", err)
	}
	for _, unit := range stopped {
		state, err := commandOutput(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit)
		if err != nil || state == "active" || state == "activating" || state == "reloading" {
			_ = resumeServices(context.Background(), stopped)
			if err != nil {
				return nil, fmt.Errorf("verify quiesced %s: %w", unit, err)
			}
			return nil, fmt.Errorf("unit_did_not_quiesce: %s is %s", unit, state)
		}
	}
	return stopped, nil
}

func quiesceSystem(ctx context.Context, current map[string]ServiceIntent, cfg Config) ([]string, bool, error) {
	stopped, err := quiesceServices(ctx, current, cfg)
	if err != nil {
		return nil, false, err
	}
	return stopped, freezeUserSlice(ctx), nil
}

func releaseQuiesce(stopped []string, frozen, resume bool) error {
	var err error
	if frozen {
		err = thawUserSlice(context.Background())
	}
	if resume {
		err = errors.Join(err, resumeServices(context.Background(), stopped))
	}
	return err
}

func resumeServices(ctx context.Context, services []string) error {
	var result error
	for _, service := range services {
		if _, err := commandOutput(ctx, "systemctl", "start", "--", service); err != nil {
			result = errors.Join(result, fmt.Errorf("resume %s: %w", service, err))
		}
	}
	return result
}

func restoreServiceIntents(ctx context.Context, intents map[string]ServiceIntent) error {
	if _, err := commandOutput(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	names := make([]string, 0, len(intents))
	for name := range intents {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		state := intents[name].UnitFileState
		switch state {
		case "enabled", "linked":
			_, _ = commandOutput(ctx, "systemctl", "unmask", name)
			if _, err := commandOutput(ctx, "systemctl", "enable", name); err != nil {
				return err
			}
		case "enabled-runtime", "linked-runtime":
			_, _ = commandOutput(ctx, "systemctl", "unmask", name)
			if _, err := commandOutput(ctx, "systemctl", "enable", "--runtime", name); err != nil {
				return err
			}
		case "masked":
			if _, err := commandOutput(ctx, "systemctl", "mask", name); err != nil {
				return err
			}
		case "masked-runtime":
			if _, err := commandOutput(ctx, "systemctl", "mask", "--runtime", name); err != nil {
				return err
			}
		case "disabled":
			_, _ = commandOutput(ctx, "systemctl", "disable", name)
		}
	}
	active := []string{}
	for _, name := range names {
		intent, ok := intents[name]
		if !ok || intent.UnitFileState == "absent" {
			continue
		}
		if intent.ActiveState == "active" {
			active = append(active, name)
		}
	}
	for _, name := range active {
		if _, err := commandOutput(ctx, "systemctl", "start", "--", name); err != nil {
			return fmt.Errorf("start restored unit %s: %w", name, err)
		}
	}
	return nil
}

func detectPackageManager() (string, error) {
	for _, candidate := range []string{"dpkg-query", "rpm", "pacman"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("unsupported_package_manager: expected dpkg-query, rpm, or pacman")
}

func packageInventory(ctx context.Context) (map[string]string, error) {
	manager, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	var out string
	switch manager {
	case "dpkg-query":
		out, err = commandOutput(ctx, manager, "-W", "-f=${binary:Package}\t${Version}\n")
	case "rpm":
		out, err = commandOutput(ctx, manager, "-qa", "--qf=%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
	case "pacman":
		out, err = commandOutput(ctx, manager, "-Q")
	}
	if err != nil {
		return nil, err
	}
	packages := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if manager == "pacman" {
			fields = strings.SplitN(line, " ", 2)
		}
		if len(fields) == 2 {
			packages[fields[0]] = fields[1]
		}
	}
	return packages, nil
}

func packageChanges(before, after map[string]string) []PackageChange {
	changes := []PackageChange{}
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	for key := range keys {
		if before[key] != after[key] {
			changes = append(changes, PackageChange{Name: key, Before: before[key], After: after[key]})
		}
	}
	slices.SortFunc(changes, func(a, b PackageChange) int { return strings.Compare(a.Name, b.Name) })
	return changes
}

func rejectCorePackageChanges(changes []PackageChange) error {
	blocked := []string{"libc6", "glibc", "systemd", "linux", "linux-image", "linux-headers", "linux-modules", "kernel", "grub", "grub2", "openssh-server", "cloud-init", "network-manager", "NetworkManager"}
	for _, change := range changes {
		for _, prefix := range blocked {
			if change.Name == prefix || strings.HasPrefix(change.Name, prefix+":") || strings.HasPrefix(change.Name, prefix+"-") || strings.HasPrefix(change.Name, prefix+".") {
				return fmt.Errorf("unsupported_core_package_change: %s %q -> %q", change.Name, change.Before, change.After)
			}
		}
	}
	return nil
}

func accountInventory() (map[string]AccountFile, error) {
	return accountInventoryPaths(accountPaths)
}

func accountInventoryPaths(paths []string) (map[string]AccountFile, error) {
	result := map[string]AccountFile{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		stat := info.Sys().(*syscall.Stat_t)
		lines := map[string]string{}
		order := []string{}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			key, _, ok := strings.Cut(line, ":")
			if ok && key != "" {
				lines[key] = line
				order = append(order, key)
			}
		}
		result[path] = AccountFile{Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid), Lines: lines, Order: order}
	}
	return result, nil
}

func accountChanges(before, after map[string]AccountFile) []AccountChange {
	changes := []AccountChange{}
	for _, path := range accountPaths {
		keys := map[string]bool{}
		for key := range before[path].Lines {
			keys[key] = true
		}
		for key := range after[path].Lines {
			keys[key] = true
		}
		for key := range keys {
			old, oldOK := before[path].Lines[key]
			current, currentOK := after[path].Lines[key]
			if oldOK == currentOK && old == current {
				continue
			}
			change := AccountChange{Path: path, Key: key}
			if oldOK {
				value := old
				change.Before = &value
			}
			if currentOK {
				value := current
				change.After = &value
			}
			changes = append(changes, change)
		}
	}
	slices.SortFunc(changes, func(a, b AccountChange) int {
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return strings.Compare(a.Key, b.Key)
	})
	return changes
}

func validateAccountChanges(changes []AccountChange, target map[string]AccountFile) error {
	for _, change := range changes {
		current, exists := target[change.Path].Lines[change.Key]
		if change.Before == nil {
			if exists && (change.After == nil || current != *change.After) {
				return fmt.Errorf("account_conflict: %s key %s already exists", change.Path, change.Key)
			}
		} else if exists && current != *change.Before && (change.After == nil || current != *change.After) {
			return fmt.Errorf("account_conflict: %s key %s diverged", change.Path, change.Key)
		}
		if change.After != nil && (change.Path == "/etc/passwd" || change.Path == "/etc/group") {
			id, ok := numericAccountID(*change.After)
			if !ok {
				return fmt.Errorf("account_conflict: malformed line for %s in %s", change.Key, change.Path)
			}
			for otherKey, line := range target[change.Path].Lines {
				otherID, valid := numericAccountID(line)
				if otherKey != change.Key && valid && otherID == id {
					return fmt.Errorf("account_conflict: %s and %s both use id %d in %s", change.Key, otherKey, id, change.Path)
				}
			}
		}
	}
	return nil
}

func numericAccountID(line string) (int, bool) {
	fields := strings.Split(line, ":")
	if len(fields) < 3 {
		return 0, false
	}
	id, err := strconv.Atoi(fields[2])
	return id, err == nil
}

func applyAccountChanges(changes []AccountChange) error {
	target, err := accountInventory()
	if err != nil {
		return err
	}
	if err := validateAccountChanges(changes, target); err != nil {
		return err
	}
	changedFiles := map[string]bool{}
	for _, change := range changes {
		file := target[change.Path]
		if change.After == nil {
			delete(file.Lines, change.Key)
		} else {
			if _, exists := file.Lines[change.Key]; !exists {
				file.Order = append(file.Order, change.Key)
			}
			file.Lines[change.Key] = *change.After
		}
		target[change.Path] = file
		changedFiles[change.Path] = true
	}
	for _, path := range accountPaths {
		if !changedFiles[path] {
			continue
		}
		file := target[path]
		var data strings.Builder
		for _, key := range file.Order {
			line, exists := file.Lines[key]
			if !exists {
				continue
			}
			data.WriteString(line)
			data.WriteByte('\n')
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".wormhole-account-*")
		if err != nil {
			return err
		}
		name := tmp.Name()
		if err := tmp.Chmod(os.FileMode(file.Mode)); err == nil {
			err = tmp.Chown(file.UID, file.GID)
		}
		if err == nil {
			_, err = tmp.WriteString(data.String())
		}
		if err == nil {
			err = copyXattrs(path, name)
		}
		if err == nil {
			err = tmp.Sync()
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, path)
		}
		if err == nil {
			err = syncDir(filepath.Dir(path))
		}
		if err != nil {
			os.Remove(name)
			return err
		}
	}
	return nil
}

func textFileInventory(paths []string) (map[string]TextFile, error) {
	files := map[string]TextFile{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				files[path] = TextFile{}
				continue
			}
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("reconciled path must be a regular file: %s", path)
		}
		stat := info.Sys().(*syscall.Stat_t)
		files[path] = TextFile{Exists: true, Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid), Lines: splitTextLines(data)}
	}
	return files, nil
}

func splitTextLines(data []byte) []string {
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func textFileChanges(before, after map[string]TextFile) []TextFileChange {
	paths := make([]string, 0, len(before)+len(after))
	for path := range before {
		paths = append(paths, path)
	}
	for path := range after {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	changes := []TextFileChange{}
	for _, path := range paths {
		oldCounts, newCounts := lineCounts(before[path].Lines), lineCounts(after[path].Lines)
		current := after[path]
		change := TextFileChange{Path: path, AfterExists: current.Exists, Mode: current.Mode, UID: current.UID, GID: current.GID}
		for _, line := range before[path].Lines {
			if newCounts[line] < oldCounts[line] {
				change.Removed = append(change.Removed, line)
				oldCounts[line]--
			}
		}
		oldCounts, newCounts = lineCounts(before[path].Lines), lineCounts(after[path].Lines)
		for _, line := range after[path].Lines {
			if oldCounts[line] < newCounts[line] {
				change.Added = append(change.Added, line)
				newCounts[line]--
			}
		}
		previous := before[path]
		metadataChanged := previous.Exists != current.Exists || (current.Exists && (previous.Mode != current.Mode || previous.UID != current.UID || previous.GID != current.GID))
		if len(change.Added) > 0 || len(change.Removed) > 0 || metadataChanged {
			changes = append(changes, change)
		}
	}
	return changes
}

func lineCounts(lines []string) map[string]int {
	counts := map[string]int{}
	for _, line := range lines {
		counts[line]++
	}
	return counts
}

func applyTextFileChanges(changes []TextFileChange, allowed []string, baselineHost, sourceHost, targetHost HostIdentity) error {
	allowedSet := map[string]bool{}
	for _, path := range allowed {
		allowedSet[path] = true
	}
	for _, change := range changes {
		if !allowedSet[change.Path] {
			return fmt.Errorf("unapproved_reconciled_path: %s", change.Path)
		}
		files, err := textFileInventory([]string{change.Path})
		if err != nil {
			return err
		}
		file := files[change.Path]
		if !file.Exists {
			if !change.AfterExists {
				continue
			}
			file = TextFile{Exists: true, Mode: change.Mode, UID: change.UID, GID: change.GID}
		} else if change.AfterExists {
			file.Mode, file.UID, file.GID = change.Mode, change.UID, change.GID
		}
		cloudTemplate := ""
		if change.Path == "/etc/hosts" {
			cloudTemplate = cloudInitHostsTemplate(file.Lines, "/etc/cloud/templates")
		}
		file.Lines = applyTextLineChanges(file.Lines, change, baselineHost, sourceHost, targetHost)
		if err := writeTextFile(change.Path, file); err != nil {
			return err
		}
		if cloudTemplate != "" {
			if err := applyCloudInitHostsTemplate(cloudTemplate, change, baselineHost, sourceHost, targetHost); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyTextLineChanges(lines []string, change TextFileChange, baselineHost, sourceHost, targetHost HostIdentity) []string {
	for _, line := range change.Removed {
		if !preserveTargetLine(change.Path, line, baselineHost) {
			lines = removeOneLine(lines, translateHostLine(change.Path, line, baselineHost, targetHost))
		}
	}
	for _, line := range change.Added {
		line = translateHostLine(change.Path, line, sourceHost, targetHost)
		if !slices.Contains(lines, line) {
			lines = append(lines, line)
		}
	}
	return lines
}

func cloudInitHostsTemplate(lines []string, dir string) string {
	prefix := filepath.Join(dir, "hosts")
	for _, line := range lines {
		start := strings.Index(line, prefix)
		if start < 0 {
			continue
		}
		path := line[start:]
		end := strings.Index(path, ".tmpl")
		if end >= 0 {
			path = filepath.Clean(path[:end+len(".tmpl")])
			if filepath.Dir(path) == filepath.Clean(dir) {
				return path
			}
		}
	}
	return ""
}

func applyCloudInitHostsTemplate(path string, change TextFileChange, baselineHost, sourceHost, targetHost HostIdentity) error {
	files, err := textFileInventory([]string{path})
	if err != nil {
		return err
	}
	file := files[path]
	file.Lines = applyTextLineChanges(file.Lines, change, baselineHost, sourceHost, targetHost)
	return writeTextFile(path, file)
}

func preserveTargetLine(path, line string, source HostIdentity) bool {
	if strings.HasSuffix(path, "/.ssh/authorized_keys") {
		return true
	}
	if path != "/etc/hosts" {
		return false
	}
	fields := strings.Fields(line)
	for _, field := range fields {
		if strings.HasPrefix(field, "#") {
			break
		}
		if field == source.Hostname {
			return true
		}
		for _, address := range source.Addresses {
			ip, _, err := net.ParseCIDR(address)
			if err == nil && field == ip.String() {
				return true
			}
		}
	}
	return false
}

func removeOneLine(lines []string, value string) []string {
	for i, line := range lines {
		if line == value {
			return append(lines[:i], lines[i+1:]...)
		}
	}
	return lines
}

func translateHostLine(path, line string, source, target HostIdentity) string {
	if path != "/etc/hosts" || source.Hostname == "" || source.Hostname == target.Hostname {
		return line
	}
	fields := strings.Fields(line)
	changed := false
	for i := 1; i < len(fields) && !strings.HasPrefix(fields[i], "#"); i++ {
		if fields[i] == source.Hostname {
			fields[i], changed = target.Hostname, true
		}
	}
	if changed && len(fields) > 1 {
		if replacement := correspondingAddress(fields[0], source.Addresses, target.Addresses); replacement != "" {
			fields[0] = replacement
		}
	}
	if changed {
		return strings.Join(fields, "\t")
	}
	return line
}

func correspondingAddress(value string, source, target []string) string {
	wanted := net.ParseIP(value)
	if wanted == nil {
		return ""
	}
	matched := false
	for _, address := range source {
		ip, _, err := net.ParseCIDR(address)
		if err == nil && ip.Equal(wanted) {
			matched = true
			break
		}
	}
	if !matched {
		return ""
	}
	for _, address := range target {
		ip, _, err := net.ParseCIDR(address)
		if err == nil && (ip.To4() != nil) == (wanted.To4() != nil) {
			return ip.String()
		}
	}
	return ""
}

func writeTextFile(path string, file TextFile) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wormhole-text-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	data := strings.Join(file.Lines, "\n")
	if len(file.Lines) > 0 {
		data += "\n"
	}
	if err = tmp.Chmod(os.FileMode(file.Mode)); err == nil {
		err = tmp.Chown(file.UID, file.GID)
	}
	if err == nil {
		_, err = tmp.WriteString(data)
	}
	if err == nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			err = copyXattrs(path, name)
		} else if !os.IsNotExist(statErr) {
			err = statErr
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	return err
}

func copyXattrs(source, target string) error {
	size, err := syscall.Listxattr(source, nil)
	if err != nil || size == 0 {
		return err
	}
	names := make([]byte, size)
	size, err = syscall.Listxattr(source, names)
	if err != nil {
		return err
	}
	for _, name := range strings.Split(strings.TrimRight(string(names[:size]), "\x00"), "\x00") {
		valueSize, err := syscall.Getxattr(source, name, nil)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return err
		}
		value := make([]byte, valueSize)
		valueSize, err = syscall.Getxattr(source, name, value)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return err
		}
		if err := syscall.Setxattr(target, name, value[:valueSize], 0); err != nil {
			return err
		}
	}
	return nil
}

func verifyTextFileChanges(changes []TextFileChange, allowed []string, baselineHost, sourceHost, targetHost HostIdentity) error {
	allowedSet := map[string]bool{}
	for _, path := range allowed {
		allowedSet[path] = true
	}
	for _, change := range changes {
		if !allowedSet[change.Path] {
			return fmt.Errorf("unapproved_reconciled_path: %s", change.Path)
		}
		files, err := textFileInventory([]string{change.Path})
		if err != nil {
			return err
		}
		file := files[change.Path]
		if change.AfterExists && !file.Exists {
			return fmt.Errorf("reconciled_file_missing: %s", change.Path)
		}
		if change.AfterExists && (file.Mode != change.Mode || file.UID != change.UID || file.GID != change.GID) {
			return fmt.Errorf("reconciled_metadata_mismatch: %s", change.Path)
		}
		lines := file.Lines
		for _, line := range change.Removed {
			if preserveTargetLine(change.Path, line, baselineHost) {
				continue
			}
			if slices.Contains(lines, translateHostLine(change.Path, line, baselineHost, targetHost)) {
				return fmt.Errorf("reconciled_line_still_present: %s", change.Path)
			}
		}
		for _, line := range change.Added {
			if !slices.Contains(lines, translateHostLine(change.Path, line, sourceHost, targetHost)) {
				return fmt.Errorf("reconciled_line_missing: %s", change.Path)
			}
		}
	}
	return nil
}

func verifyAccountChanges(changes []AccountChange) error {
	current, err := accountInventory()
	if err != nil {
		return err
	}
	for _, change := range changes {
		line, exists := current[change.Path].Lines[change.Key]
		if change.After == nil && exists {
			return fmt.Errorf("account_still_present: %s key %s", change.Path, change.Key)
		}
		if change.After != nil && (!exists || line != *change.After) {
			return fmt.Errorf("account_restore_mismatch: %s key %s", change.Path, change.Key)
		}
	}
	return nil
}

func verifyPackageChanges(ctx context.Context, changes []PackageChange) error {
	current, err := packageInventory(ctx)
	if err != nil {
		return err
	}
	for _, change := range changes {
		version, exists := current[change.Name]
		if change.After == "" && exists {
			return fmt.Errorf("package_still_present: %s", change.Name)
		}
		if change.After != "" && (!exists || version != change.After) {
			return fmt.Errorf("package_restore_mismatch: %s expected %q, got %q", change.Name, change.After, version)
		}
	}
	return nil
}

func verifyWorkloads(ctx context.Context, services map[string]ServiceIntent) error {
	current, err := serviceIntents(ctx)
	if err != nil {
		return err
	}
	for name, expected := range services {
		actual, exists := current[name]
		if !exists {
			return fmt.Errorf("unit_missing: %s", name)
		}
		if unitFileStateClass(actual.UnitFileState) != unitFileStateClass(expected.UnitFileState) {
			return fmt.Errorf("unit_file_state_mismatch: %s expected %s, got %s", name, expected.UnitFileState, actual.UnitFileState)
		}
		if (actual.ActiveState == "active") != (expected.ActiveState == "active") {
			return fmt.Errorf("unit_active_state_mismatch: %s expected %s, got %s", name, expected.ActiveState, actual.ActiveState)
		}
	}
	return nil
}

func unitFileStateClass(state string) string {
	if state == "linked" {
		return "enabled"
	}
	if state == "linked-runtime" {
		return "enabled-runtime"
	}
	return state
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func commandInput(ctx context.Context, input, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
