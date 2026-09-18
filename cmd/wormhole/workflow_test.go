package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestGenericChangePlan(t *testing.T) {
	cfg := Config{Roots: []string{"/"}, Exclude: []string{"/var/lib/wormhole/**"}, ProtectedServices: []string{"ssh.service", "getty@.service"}}
	changes := []Change{
		{Path: "/opt/lab/file[1]", Modifier: "M"},
		{Path: "/var/lib/anything/data\nfile", Modifier: "+"},
		{Path: "/etc/old-lab.conf", Modifier: "-"},
	}
	if err := validateChanges(changes, cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/lab/file[1]", "/var/lib/anything/data\nfile"}
	if got := restorePathList(changes); !reflect.DeepEqual(got, want) {
		t.Fatalf("restore paths: want %#v, got %#v", want, got)
	}
	if err := validateChanges([]Change{{Path: "/etc/machine-id", Modifier: "M"}}, cfg); err == nil {
		t.Fatal("protected machine identity was accepted")
	}
	if err := validateChanges([]Change{{Path: "/", Modifier: "U"}}, cfg); err != nil {
		t.Fatalf("managed root metadata was rejected: %v", err)
	}
	if err := validateChanges([]Change{{Path: "/", Modifier: "-"}}, cfg); err == nil {
		t.Fatal("managed root deletion was accepted")
	}
	if err := validateChanges([]Change{{Path: "/var/lib/wormhole/jobs/x", Modifier: "+"}}, cfg); err == nil {
		t.Fatal("configured exclusion was accepted")
	}
	if !isExcludedPath("/etc/netplan/50-cloud-init.yaml", defaultExcludes) || !isExcludedPath("/etc/NetworkManager/system-connections/cloud-init-eth0.nmconnection", defaultExcludes) || !isExcludedPath("/etc/resolv.conf", defaultExcludes) {
		t.Fatal("provider network identity was not excluded")
	}
	if isExcludedPath("/etc/systemd/system/wormhole-fixture-writer.service", defaultExcludes) || !isExcludedPath("/etc/systemd/system/wormhole-capture@.service", defaultExcludes) {
		t.Fatal("Wormhole unit protection matched a workload unit")
	}
	if isExcludedPath("/var/log/nginx", defaultExcludes) || !isExcludedPath("/var/log/nginx/error.log", defaultExcludes) {
		t.Fatal("log policy did not preserve required directory structure")
	}
	if !isExcludedPath("/var/log/sysstat/sa16", defaultExcludes) {
		t.Fatal("volatile sysstat data was not excluded")
	}
	if !isExcludedPath("/var/lib/command-not-found/commands.db.metadata", defaultExcludes) {
		t.Fatal("volatile package command cache was not excluded")
	}
	if !isExcludedPath("/var/lib/dnf/repos/appstream-deadbeef/countme", defaultExcludes) {
		t.Fatal("volatile DNF mirror telemetry was not excluded")
	}
	if !isExcludedPath("/var/lib/plymouth/boot-duration", defaultExcludes) || !isExcludedPath("/var/lib/wtmpdb/wtmp.db", defaultExcludes) {
		t.Fatal("volatile boot and login accounting state was not excluded")
	}
	if !isExcludedPath("/var/log/wtmp.db", defaultExcludes) || !isExcludedPath("/var/lib/lastlog/lastlog2.db", defaultExcludes) || !isExcludedPath("/var/lib/logrotate/status", defaultExcludes) || !isExcludedPath("/var/lib/chrony/example.nts", defaultExcludes) || !isExcludedPath("/var/spool/anacron/cron.daily", defaultExcludes) {
		t.Fatal("volatile service state was not excluded")
	}
	if !isExcludedPath("/var/lib/unbound/root.key", defaultExcludes) {
		t.Fatal("host-managed DNSSEC trust anchor was not excluded")
	}
	if !isExcludedPath("/var/lib/ubuntu-advantage/apt-esm/var/cache/apt/pkgcache.bin", defaultExcludes) {
		t.Fatal("host-managed Ubuntu Pro state was not excluded")
	}
}

func TestTargetDriftAllowsOnlyPlannedPaths(t *testing.T) {
	drift := []Change{{Path: "/opt/lab/replaced", Modifier: "M"}, {Path: "/opt/lab/unrelated", Modifier: "+"}}
	planned := []Change{{Path: "/opt/lab/replaced", Modifier: "+"}}
	got := unexpectedTargetDrift(drift, planned)
	if !reflect.DeepEqual(got, drift[1:]) {
		t.Fatalf("unexpected target drift filter: %#v", got)
	}
	if got := changesAtPlannedPaths(drift, planned); !reflect.DeepEqual(got, drift[:1]) {
		t.Fatalf("planned target drift filter: %#v", got)
	}
}

func TestServiceSelectionIsGeneric(t *testing.T) {
	cfg := Config{ProtectedServices: []string{"ssh.service", "getty@.service", "agent.service"}, QuiesceServices: []string{"agent.service"}}
	services := map[string]ServiceIntent{
		"ssh.service":          {ActiveState: "active"},
		"getty@tty1.service":   {ActiveState: "active"},
		"postgresql.service":   {ActiveState: "active"},
		"host-unchanged.timer": {ActiveState: "active"},
		"host-changed.service": {ActiveState: "active"},
		"some-new-lab.service": {ActiveState: "inactive"},
		"runtime-task.scope":   {ActiveState: "active"},
		"agent.service":        {ActiveState: "active"},
		"booting.service":      {UnitFileState: "enabled", ActiveState: "activating", SubState: "start"},
	}
	baseline := map[string]ServiceIntent{
		"host-unchanged.timer": {ActiveState: "active"},
		"host-changed.service": {ActiveState: "inactive"},
		"booting.service":      {UnitFileState: "enabled", ActiveState: "active", SubState: "running"},
	}
	got := workloadServiceIntents(services, baseline, cfg)
	if _, ok := got["ssh.service"]; ok {
		t.Fatal("protected host service selected")
	}
	if _, ok := got["getty@tty1.service"]; ok {
		t.Fatal("protected template service selected")
	}
	if len(got) != 4 || got["postgresql.service"].ActiveState != "active" || got["agent.service"].ActiveState != "active" || got["host-changed.service"].ActiveState != "active" {
		t.Fatalf("generic workload services not preserved: %#v", got)
	}
	if stableActiveState("activating") != "active" || stableActiveState("deactivating") != "inactive" {
		t.Fatal("transitional systemd state was not normalized")
	}
	if !isProtectedService("systemd-networkd.socket", nil) || !isProtectedService("auditd.service", defaultProtectedServices) || !isProtectedService("dbus-broker.service", defaultProtectedServices) {
		t.Fatal("systemd host unit was not protected")
	}
}

func TestOnlyNewMountUnitsBecomeWorkloadIntent(t *testing.T) {
	baseline := map[string]ServiceIntent{
		"-.mount": {ActiveState: "active"},
	}
	current := map[string]ServiceIntent{
		"-.mount":                    {ActiveState: "active"},
		"srv-course.mount":           {UnitFileState: "enabled", ActiveState: "active"},
		"run-docker-netns-123.mount": {ActiveState: "active"},
	}
	got := workloadServiceIntents(current, baseline, Config{})
	if _, exists := got["-.mount"]; exists {
		t.Fatal("baseline host mount was selected for restore")
	}
	if got["srv-course.mount"].ActiveState != "active" {
		t.Fatalf("new lab mount was not selected: %#v", got)
	}
	if _, exists := got["run-docker-netns-123.mount"]; exists {
		t.Fatal("transient runtime mount was selected for restore")
	}
}

func TestRuntimeUnitIntentStaysRuntime(t *testing.T) {
	if unitFileStateClass("linked") != "enabled" || unitFileStateClass("linked-runtime") != "enabled-runtime" {
		t.Fatal("linked unit state was classified incorrectly")
	}
	if unitFileStateClass("enabled-runtime") == unitFileStateClass("enabled") || unitFileStateClass("masked-runtime") == unitFileStateClass("masked") {
		t.Fatal("runtime unit intent was treated as persistent")
	}
}

func TestConfigHashIncludesSafetyPolicy(t *testing.T) {
	base := Config{Roots: []string{"/"}, Exclude: []string{"/run"}, RestoreVerify: true, RequireSourceFence: true}
	changed := base
	changed.RestoreVerify = false
	if configHash(base) == configHash(changed) {
		t.Fatal("restore verification policy was omitted from config hash")
	}
}

func TestMountSelectionUsesDeepestMount(t *testing.T) {
	mounts := []mountInfo{{Path: "/", Filesystem: "ext4"}, {Path: "/srv/labs", Filesystem: "xfs"}}
	got, ok := mountForPath("/srv/labs/a/data", mounts)
	if !ok || got.Path != "/srv/labs" || got.Filesystem != "xfs" {
		t.Fatalf("wrong mount selected: %#v, %v", got, ok)
	}
	if got := unescapeMountPath(`/srv/lab\040data`); got != "/srv/lab data" {
		t.Fatalf("mount escape was not decoded: %q", got)
	}
	if !transientFilesystem("overlay") || !transientFilesystem("tmpfs") || transientFilesystem("ext4") {
		t.Fatal("transient filesystem classification is wrong")
	}
	mounts = append(mounts, mountInfo{Path: "/srv/labs/a/merged", Filesystem: "overlay"})
	got, ok = persistentMountForPath("/srv/labs/a/merged", mounts)
	if !ok || got.Path != "/srv/labs" {
		t.Fatalf("transient mount was used for storage preflight: %#v, %v", got, ok)
	}
}

func TestOperationLockRejectsOverlap(t *testing.T) {
	dir := t.TempDir()
	unlock, err := acquireOperationLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if secondUnlock, err := acquireOperationLock(dir); err == nil {
		secondUnlock()
		t.Fatal("overlapping operation acquired the same lock")
	}
}

func TestResumeAcceptsPartialFirewallState(t *testing.T) {
	baseline := FirewallState{Backend: "nft", Rules: "baseline"}
	captured := FirewallState{Backend: "nft", Rules: "captured"}
	partial := FirewallState{Backend: "nft", Rules: "partial"}
	if err := validateTargetFirewall(baseline, captured, partial, false); err == nil {
		t.Fatal("fresh restore accepted a partial firewall state")
	}
	if err := validateTargetFirewall(baseline, captured, partial, true); err != nil {
		t.Fatalf("resume rejected its partial firewall state: %v", err)
	}
}

func TestScheduleUserSliceThawAfterCallingUnitExits(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\n" +
		"printf '%s %s\\n' \"${0##*/}\" \"$*\" >>\"$WORMHOLE_SYSTEMCTL_LOG\"\n" +
		"[ \"${0##*/}\" != systemctl ]\n"
	if err := os.WriteFile(systemctl, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("WORMHOLE_SYSTEMCTL_LOG", logPath)
	if err := scheduleUserSliceThaw(context.Background(), "wormhole-test.service"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	want := fmt.Sprintf("systemd-run --quiet --collect --unit=wormhole-thaw-sessions-%d /bin/sh -c while state=$(systemctl show --property=ActiveState --value \"$1\" 2>/dev/null); do case \"$state\" in inactive|failed) break;; esac; sleep 1; done; systemctl thaw user.slice session-*.scope sh wormhole-test.service\n", os.Getpid())
	if got != want {
		t.Fatalf("unexpected systemctl calls: %q", got)
	}
}

func TestCurrentSystemdUnit(t *testing.T) {
	for input, want := range map[string]string{
		"0::/system.slice/wormhole-baseline.service\n":                         "wormhole-baseline.service",
		"0::/user.slice/user-1000.slice/user@1000.service/session-4.scope\n":   "session-4.scope",
		"11:memory:/\n1:name=systemd:/system.slice/wormhole-capture.service\n": "wormhole-capture.service",
	} {
		if got := systemdUnit([]byte(input)); got != want {
			t.Fatalf("systemd unit: want %q, got %q", want, got)
		}
	}
}

func TestCommitRestoredBaseline(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	baseline := Baseline{Schema: schemaVersion, EngineCommit: engineCommit, EnvironmentID: "lab", SnapshotID: "base", ExclusionSetHash: "policy"}
	if err := commitRestoredBaseline(baselinePath, baseline); err != nil {
		t.Fatal(err)
	}
	var got Baseline
	if err := readJSON(baselinePath, &got); err != nil || got.SnapshotID != "base" {
		t.Fatalf("restored baseline was not committed: %#v, %v", got, err)
	}
	conflict := baseline
	conflict.SnapshotID = "other"
	if err := commitRestoredBaseline(baselinePath, conflict); err == nil {
		t.Fatal("conflicting restored baseline was accepted")
	}
}

func TestTextFileDeltaPreservesTargetAndMapsHostIdentity(t *testing.T) {
	before := map[string]TextFile{"/etc/hosts": {Lines: []string{"127.0.0.1 localhost", "10.0.0.1 old-host"}}}
	after := map[string]TextFile{"/etc/hosts": {Lines: []string{"127.0.0.1 localhost", "10.0.0.1 old-host lab-alias", "192.0.2.4 course.test"}}}
	changes := textFileChanges(before, after)
	if len(changes) != 1 || len(changes[0].Removed) != 1 || len(changes[0].Added) != 2 {
		t.Fatalf("unexpected text delta: %#v", changes)
	}
	source := HostIdentity{Hostname: "old-host", Addresses: []string{"10.0.0.1/24"}}
	target := HostIdentity{Hostname: "new-host", Addresses: []string{"10.0.0.2/24"}}
	got := translateHostLine("/etc/hosts", changes[0].Added[0], source, target)
	if got != "10.0.0.2\tnew-host\tlab-alias" {
		t.Fatalf("host identity was not mapped: %q", got)
	}
	if !preserveTargetLine("/root/.ssh/authorized_keys", "ssh-ed25519 provider", source) || !preserveTargetLine("/etc/hosts", "10.0.0.1 old-host", source) {
		t.Fatal("provider access or host identity line was not protected")
	}
}

func TestCloudInitHostsTemplatePersistsReconciledLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.suse.tmpl")
	if err := os.WriteFile(path, []byte("127.0.0.1 {{fqdn}} {{hostname}}\n192.0.2.1 removed.test\n"), 0640); err != nil {
		t.Fatal(err)
	}
	inactive := filepath.Join(dir, "hosts.debian.tmpl")
	if err := os.WriteFile(inactive, []byte("inactive\n"), 0644); err != nil {
		t.Fatal(err)
	}
	hosts := []string{"# Changes persist in the master file " + path}
	if got := cloudInitHostsTemplate(hosts, dir); got != path {
		t.Fatalf("active hosts template: want %q, got %q", path, got)
	}
	if got := cloudInitHostsTemplate([]string{"# " + filepath.Join(dir, "hosts..", "escape.tmpl")}, dir); got != "" {
		t.Fatalf("accepted hosts template outside its directory: %q", got)
	}
	change := TextFileChange{Path: "/etc/hosts", Added: []string{"192.0.2.123 course.test"}, Removed: []string{"192.0.2.1 removed.test"}}
	for range 2 {
		if err := applyCloudInitHostsTemplate(path, change, HostIdentity{}, HostIdentity{}, HostIdentity{}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "127.0.0.1 {{fqdn}} {{hostname}}\n192.0.2.123 course.test\n" {
		t.Fatalf("unexpected persisted hosts template: %q", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("template metadata changed: %v, %v", info, err)
	}
	if data, err := os.ReadFile(inactive); err != nil || string(data) != "inactive\n" {
		t.Fatalf("inactive template changed: %q, %v", data, err)
	}
}

func TestNewAuthorizedKeyFileUsesReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	after := map[string]TextFile{path: {Exists: true, Mode: 0600, UID: os.Geteuid(), GID: os.Getegid(), Lines: []string{"ssh-ed25519 lab-key"}}}
	changes := textFileChanges(nil, after)
	if len(changes) != 1 || !changes[0].AfterExists || changes[0].Mode != 0600 {
		t.Fatalf("new authorized key was not represented: %#v", changes)
	}
	if err := applyTextFileChanges(changes, []string{path}, HostIdentity{}, HostIdentity{}, HostIdentity{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "ssh-ed25519 lab-key\n" {
		t.Fatalf("new authorized key was not reconciled: %q, %v", data, err)
	}
}

func TestAccountInventoryAllowsMissingOptionalFile(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := accountInventoryPaths([]string{passwd, filepath.Join(dir, "gshadow")})
	if err != nil || len(files) != 1 || files[passwd].Lines["root"] == "" {
		t.Fatalf("optional account file inventory failed: %#v, %v", files, err)
	}
}

func TestFirewallCountersArePortable(t *testing.T) {
	rules := ":INPUT ACCEPT [12:345]\n:OUTPUT ACCEPT [9:99]"
	if got := normalizeFirewallCounters(rules); got != ":INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]" {
		t.Fatalf("firewall counters were not normalized: %q", got)
	}
}

func TestNFTConnectionStateOrderIsPortable(t *testing.T) {
	rules := "ct state related,established counter accept"
	if got := normalizeNFTRules(rules); got != "ct state established,related counter accept" {
		t.Fatalf("nft connection states were not normalized: %q", got)
	}
}

func TestEnvironmentIDValidation(t *testing.T) {
	if err := validateEnvironmentID("lab_123.eu-west"); err != nil {
		t.Fatal(err)
	}
	if err := validateEnvironmentID("lab:123\nother-tag"); err == nil {
		t.Fatal("unsafe environment ID was accepted")
	}
}

func TestHostIdentityPathsAreProtected(t *testing.T) {
	if !isProtectedPath("/etc/machine-id") || !isProtectedPath("/etc/netplan/50-cloud-init.yaml") {
		t.Fatal("host identity path was not protected")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(`{"reconcile_files":["/etc/machine-id"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(config, filepath.Join(dir, "state")); err == nil {
		t.Fatal("protected host identity was accepted as a reconciled file")
	}
}

func TestSysctlDeltaIsPortable(t *testing.T) {
	before := map[string]string{"net/ipv4/ip_forward": "0", "kernel/hostname": "old", "net/ipv4/conf/eth0/rp_filter": "2"}
	after := map[string]string{"net/ipv4/ip_forward": "1", "kernel/hostname": "new", "net/ipv4/conf/eth0/rp_filter": "1"}
	changes := sysctlChanges(before, after)
	if len(changes) != 3 { // inventory filtering happens before delta calculation
		t.Fatalf("unexpected sysctl delta: %#v", changes)
	}
	if !portableSysctl("net/ipv4/ip_forward") || !portableSysctl("net/ipv4/conf/default/rp_filter") {
		t.Fatal("portable sysctl was rejected")
	}
	if portableSysctl("kernel/hostname") || portableSysctl("net/ipv4/conf/eth0/rp_filter") ||
		portableSysctl("net/ipv4/tcp_fastopen_key") || portableSysctl("kernel/sched_domain/cpu0/domain0/max_newidle_lb_cost") ||
		portableSysctl("kernel/threads-max") || portableSysctl("net/ipv4/tcp_rmem") || portableSysctl("user/max_net_namespaces") || portableSysctl("vm/user_reserve_kbytes") {
		t.Fatal("machine-specific sysctl was accepted")
	}
	if err := validateSysctlChanges(changes[:1], map[string]string{changes[0].Name: changes[0].Before}); err != nil {
		t.Fatal(err)
	}
	if err := validateSysctlChanges(changes[:1], map[string]string{changes[0].Name: "target-default"}); err != nil {
		t.Fatalf("portable target default was rejected: %v", err)
	}
}

func TestKernelModuleAdditions(t *testing.T) {
	added, err := kernelModuleAdditions([]string{"base", "shared"}, []string{"course_lab", "shared", "base"})
	if err != nil || !reflect.DeepEqual(added, []string{"course_lab"}) {
		t.Fatalf("unexpected kernel module delta: %#v, %v", added, err)
	}
	added, err = kernelModuleAdditions([]string{"base", "removed"}, []string{"base"})
	if err != nil || len(added) != 0 {
		t.Fatalf("baseline module removal was not safely ignored: %#v, %v", added, err)
	}
}

func TestSELinuxRuntimeTransition(t *testing.T) {
	if err := validateSecurityChange(SecurityState{SELinux: "Enforcing"}, SecurityState{SELinux: "Permissive"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurityChange(SecurityState{SELinux: "Disabled"}, SecurityState{SELinux: "Permissive"}); err == nil {
		t.Fatal("runtime transition from disabled SELinux was accepted")
	}
	if err := validateTargetSecurity(SecurityState{SELinux: "Enforcing"}, SecurityState{SELinux: "Permissive"}, SecurityState{SELinux: "Disabled"}); err == nil {
		t.Fatal("incompatible target SELinux state was accepted")
	}
}

func TestSafeRemoveRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "keep")
	if err := os.WriteFile(victim, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := safeRemove(filepath.Join(root, "link", "keep"), Config{Roots: []string{root}}); err == nil {
		t.Fatal("deletion followed a symlinked parent")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("outside file was removed: %v", err)
	}
}

func TestCopyXattrs(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(source, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(source, "user.wormhole", []byte("kept"), 0); err != nil {
		t.Skipf("filesystem does not support user xattrs: %v", err)
	}
	if err := copyXattrs(source, target); err != nil {
		t.Fatal(err)
	}
	value := make([]byte, 16)
	n, err := syscall.Getxattr(target, "user.wormhole", value)
	if err != nil || string(value[:n]) != "kept" {
		t.Fatalf("xattr was not copied: %q, %v", value[:n], err)
	}
}
