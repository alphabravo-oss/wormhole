package main

import "time"

const schemaVersion = 8

type Config struct {
	Roots              []string `json:"roots"`
	Exclude            []string `json:"exclude"`
	QuiesceServices    []string `json:"quiesce_services,omitempty"`
	ProtectedServices  []string `json:"protected_services,omitempty"`
	ReconcileFiles     []string `json:"reconcile_files,omitempty"`
	OneFileSystem      bool     `json:"one_file_system"`
	RestoreVerify      bool     `json:"restore_verify"`
	RequireSourceFence bool     `json:"require_source_fence"`
}

type SystemInfo struct {
	OSID           string `json:"os_id"`
	OSVersion      string `json:"os_version"`
	Architecture   string `json:"architecture"`
	Kernel         string `json:"kernel"`
	CgroupVersion  string `json:"cgroup_version"`
	PackageManager string `json:"package_manager"`
}

type HostIdentity struct {
	Hostname      string   `json:"hostname"`
	MachineID     string   `json:"machine_id,omitempty"`
	SSHHostKeys   string   `json:"ssh_host_keys_sha256,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	DefaultRoutes string   `json:"default_routes_sha256,omitempty"`
}

type ServiceIntent struct {
	UnitFileState string `json:"unit_file_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state,omitempty"`
}

type AccountFile struct {
	Mode  uint32            `json:"mode"`
	UID   int               `json:"uid"`
	GID   int               `json:"gid"`
	Lines map[string]string `json:"lines"`
	Order []string          `json:"order"`
}

type AccountChange struct {
	Path   string  `json:"path"`
	Key    string  `json:"key"`
	Before *string `json:"before,omitempty"`
	After  *string `json:"after,omitempty"`
}

type TextFile struct {
	Exists bool     `json:"exists"`
	Mode   uint32   `json:"mode"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	Lines  []string `json:"lines"`
}

type TextFileChange struct {
	Path        string   `json:"path"`
	Added       []string `json:"added,omitempty"`
	Removed     []string `json:"removed,omitempty"`
	AfterExists bool     `json:"after_exists"`
	Mode        uint32   `json:"mode,omitempty"`
	UID         int      `json:"uid,omitempty"`
	GID         int      `json:"gid,omitempty"`
}

type PackageChange struct {
	Name   string `json:"name"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type Change struct {
	Path     string `json:"path"`
	Modifier string `json:"modifier"`
}

type StorageRequirement struct {
	MountPoint string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	Bytes      uint64 `json:"bytes"`
	Inodes     uint64 `json:"inodes"`
}

type FirewallState struct {
	Backend string `json:"backend"`
	Rules   string `json:"rules,omitempty"`
	RulesV6 string `json:"rules_v6,omitempty"`
}

type SecurityState struct {
	SELinux string `json:"selinux,omitempty"`
}

type SysctlChange struct {
	Name   string `json:"name"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type Baseline struct {
	Schema           int                      `json:"schema"`
	EnvironmentID    string                   `json:"environment_id"`
	CreatedAt        time.Time                `json:"created_at"`
	SnapshotID       string                   `json:"snapshot_id"`
	EngineCommit     string                   `json:"engine_commit"`
	Config           Config                   `json:"config"`
	System           SystemInfo               `json:"system"`
	Host             HostIdentity             `json:"host"`
	Services         map[string]ServiceIntent `json:"services"`
	Packages         map[string]string        `json:"packages"`
	Accounts         map[string]AccountFile   `json:"accounts"`
	ReconciledFiles  map[string]TextFile      `json:"reconciled_files,omitempty"`
	Firewall         FirewallState            `json:"firewall"`
	Sysctls          map[string]string        `json:"sysctls,omitempty"`
	KernelModules    []string                 `json:"kernel_modules,omitempty"`
	Security         SecurityState            `json:"security"`
	ExclusionSetHash string                   `json:"exclusion_set_sha256"`
}

type Manifest struct {
	Schema              int                      `json:"schema"`
	CaptureID           string                   `json:"capture_id"`
	EnvironmentID       string                   `json:"environment_id"`
	CreatedAt           time.Time                `json:"created_at"`
	BaselineSnapshotID  string                   `json:"baseline_snapshot_id"`
	CaptureSnapshotID   string                   `json:"capture_snapshot_id"`
	ManifestSnapshotID  string                   `json:"manifest_snapshot_id,omitempty"`
	EngineCommit        string                   `json:"engine_commit"`
	Config              Config                   `json:"config"`
	BaselineSystem      SystemInfo               `json:"baseline_system"`
	CapturedSystem      SystemInfo               `json:"captured_system"`
	BaselineHost        HostIdentity             `json:"baseline_host"`
	SourceHost          HostIdentity             `json:"source_host"`
	Changes             []Change                 `json:"changes"`
	ServiceIntents      map[string]ServiceIntent `json:"service_intents,omitempty"`
	AccountChanges      []AccountChange          `json:"account_changes,omitempty"`
	TextFileChanges     []TextFileChange         `json:"text_file_changes,omitempty"`
	PackageChanges      []PackageChange          `json:"package_changes,omitempty"`
	StorageRequirements []StorageRequirement     `json:"storage_requirements,omitempty"`
	BaselineFirewall    FirewallState            `json:"baseline_firewall"`
	CapturedFirewall    FirewallState            `json:"captured_firewall"`
	SysctlChanges       []SysctlChange           `json:"sysctl_changes,omitempty"`
	KernelModulesAdded  []string                 `json:"kernel_modules_added,omitempty"`
	BaselineSecurity    SecurityState            `json:"baseline_security"`
	CapturedSecurity    SecurityState            `json:"captured_security"`
	ExclusionSetHash    string                   `json:"exclusion_set_sha256"`
	Consistency         string                   `json:"consistency"`
	CaptureDataAdded    uint64                   `json:"capture_data_added"`
	CaptureDataPacked   uint64                   `json:"capture_data_added_packed"`
	CaptureFilesNew     uint                     `json:"capture_files_new"`
	CaptureFilesChanged uint                     `json:"capture_files_changed"`
	CaptureDirsNew      uint                     `json:"capture_dirs_new"`
	CaptureDirsChanged  uint                     `json:"capture_dirs_changed"`
}

type Job struct {
	ID               string       `json:"id"`
	Kind             string       `json:"kind"`
	Status           string       `json:"status"`
	Phase            string       `json:"phase"`
	StartedAt        time.Time    `json:"started_at"`
	FinishedAt       *time.Time   `json:"finished_at,omitempty"`
	CaptureID        string       `json:"capture_id,omitempty"`
	SnapshotID       string       `json:"snapshot_id,omitempty"`
	TargetHostBefore HostIdentity `json:"target_host_before,omitempty"`
	TargetHostAfter  HostIdentity `json:"target_host_after,omitempty"`
	VerificationID   string       `json:"verification_snapshot_id,omitempty"`
	Error            string       `json:"error,omitempty"`
}

type backupSummary struct {
	MessageType     string `json:"message_type"`
	SnapshotID      string `json:"snapshot_id"`
	FilesNew        uint   `json:"files_new"`
	FilesChanged    uint   `json:"files_changed"`
	DirsNew         uint   `json:"dirs_new"`
	DirsChanged     uint   `json:"dirs_changed"`
	DataAdded       uint64 `json:"data_added"`
	DataAddedPacked uint64 `json:"data_added_packed"`
}

type resticSnapshot struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	Tags []string  `json:"tags"`
}

type diffEvent struct {
	MessageType string `json:"message_type"`
	Path        string `json:"path"`
	Modifier    string `json:"modifier"`
}
