package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

func createBaseline(ctx context.Context, common commonFlags) (returnErr error) {
	if err := validateEnvironmentID(common.environment); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := validateRepositoryEnvironment(); err != nil {
		return err
	}
	if err := ensureStateDir(common.stateDir); err != nil {
		return err
	}
	unlock, err := acquireOperationLock(common.stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	baselinePath := filepath.Join(common.stateDir, "baseline.json")
	if _, err := os.Stat(baselinePath); err == nil {
		return fmt.Errorf("baseline already exists at %s", baselinePath)
	}
	cfg, err := loadConfig(common.configPath, common.stateDir)
	if err != nil {
		return err
	}
	e := engine{bin: common.resticBin, stateDir: common.stateDir}
	if err := checkEngine(ctx, e); err != nil {
		return err
	}
	if err := e.ensureRepository(ctx); err != nil {
		return err
	}
	ctx, e, releaseLease, err := e.acquireRepositoryLease(ctx)
	if err != nil {
		return err
	}
	leaseReleased := false
	defer func() {
		if !leaseReleased {
			returnErr = errors.Join(returnErr, releaseLease())
		}
	}()
	system, err := systemInfo()
	if err != nil {
		return err
	}
	host, err := hostIdentity(ctx)
	if err != nil {
		return err
	}
	services, err := serviceIntents(ctx)
	if err != nil {
		return err
	}
	firewall, err := firewallState(ctx)
	if err != nil {
		return err
	}
	sysctls, err := sysctlInventory(ctx)
	if err != nil {
		return err
	}
	kernelModules, err := kernelModuleInventory()
	if err != nil {
		return err
	}
	security, err := securityState(ctx)
	if err != nil {
		return err
	}
	stopped, frozen, err := quiesceSystem(ctx, services, cfg)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			returnErr = errors.Join(returnErr, releaseQuiesce(stopped, frozen, true))
		}
	}()
	syscall.Sync()
	accounts, err := accountInventory()
	if err != nil {
		return err
	}
	packages, err := packageInventory(ctx)
	if err != nil {
		return err
	}
	reconciled, err := textFileInventory(cfg.ReconcileFiles)
	if err != nil {
		return err
	}
	summary, err := e.backup(ctx, cfg, "", false, "wormhole-baseline", "env:"+common.environment)
	if err != nil {
		return err
	}
	baseline := Baseline{
		Schema: schemaVersion, EnvironmentID: common.environment, CreatedAt: time.Now().UTC(),
		SnapshotID: summary.SnapshotID, EngineCommit: engineCommit, Config: cfg,
		System: system, Host: host, Services: services, Packages: packages,
		Accounts: accounts, ReconciledFiles: reconciled, Firewall: firewall, Sysctls: sysctls,
		KernelModules: kernelModules, Security: security, ExclusionSetHash: configHash(cfg),
	}
	if err := writeJSONAtomic(baselinePath, baseline, 0600); err != nil {
		return err
	}
	released = true
	if err := releaseQuiesce(stopped, frozen, true); err != nil {
		return err
	}
	leaseReleased = true
	if err := releaseLease(); err != nil {
		return err
	}
	return emit(map[string]any{
		"status": "baseline_committed", "environment_id": common.environment,
		"snapshot_id": summary.SnapshotID, "logical_bytes": summary.DataAdded,
		"stored_bytes": summary.DataAddedPacked,
	})
}

func capture(ctx context.Context, common commonFlags, leaveStopped bool) (returnErr error) {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := validateRepositoryEnvironment(); err != nil {
		return err
	}
	if err := ensureStateDir(common.stateDir); err != nil {
		return err
	}
	unlock, err := acquireOperationLock(common.stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	var baseline Baseline
	if err := readJSON(filepath.Join(common.stateDir, "baseline.json"), &baseline); err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	if common.environment != "" && common.environment != baseline.EnvironmentID {
		return errors.New("environment_id_mismatch")
	}
	common.environment = baseline.EnvironmentID
	if err := validateEnvironmentID(common.environment); err != nil {
		return err
	}
	if baseline.Schema != schemaVersion || baseline.EngineCommit != engineCommit {
		return errors.New("baseline_schema_or_engine_mismatch")
	}
	if baseline.ExclusionSetHash != configHash(baseline.Config) {
		return errors.New("baseline_policy_hash_mismatch")
	}
	e := engine{bin: common.resticBin, stateDir: common.stateDir}
	if err := checkEngine(ctx, e); err != nil {
		return err
	}
	ctx, e, releaseLease, err := e.acquireRepositoryLease(ctx)
	if err != nil {
		return err
	}
	leaseReleased := false
	defer func() {
		if !leaseReleased {
			returnErr = errors.Join(returnErr, releaseLease())
		}
	}()
	system, err := systemInfo()
	if err != nil {
		return err
	}
	if err := compatibleSystem(baseline.System, system); err != nil {
		return err
	}
	host, err := hostIdentity(ctx)
	if err != nil {
		return err
	}
	services, err := serviceIntents(ctx)
	if err != nil {
		return err
	}
	firewall, err := firewallState(ctx)
	if err != nil {
		return err
	}
	sysctls, err := sysctlInventory(ctx)
	if err != nil {
		return err
	}
	kernelModules, err := kernelModuleInventory()
	if err != nil {
		return err
	}
	kernelModulesAdded, err := kernelModuleAdditions(baseline.KernelModules, kernelModules)
	if err != nil {
		return err
	}
	security, err := securityState(ctx)
	if err != nil {
		return err
	}
	if err := validateSecurityChange(baseline.Security, security); err != nil {
		return err
	}
	captureID := newID()
	job := Job{ID: captureID, Kind: "capture", Status: "running", Phase: "quiesce", StartedAt: time.Now().UTC(), CaptureID: captureID}
	jobPath := filepath.Join(common.stateDir, "jobs", captureID+".json")
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			job.Status, job.Error = "failed", returnErr.Error()
			_ = writeJSONAtomic(jobPath, job, 0600)
		}
	}()
	stopped, frozen, err := quiesceSystem(ctx, services, baseline.Config)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			returnErr = errors.Join(returnErr, releaseQuiesce(stopped, frozen, !leaveStopped || returnErr != nil))
		}
	}()
	syscall.Sync()
	captureConfig, err := extendReconcileFiles(baseline.Config, discoverAuthorizedKeys())
	if err != nil {
		return err
	}
	accounts, err := accountInventory()
	if err != nil {
		return err
	}
	packages, err := packageInventory(ctx)
	if err != nil {
		return err
	}
	reconciled, err := textFileInventory(captureConfig.ReconcileFiles)
	if err != nil {
		return err
	}
	packageDelta := packageChanges(baseline.Packages, packages)
	if err := rejectCorePackageChanges(packageDelta); err != nil {
		return err
	}
	job.Phase = "backup"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	summary, err := e.backup(ctx, captureConfig, baseline.SnapshotID, false,
		"wormhole-data", "env:"+common.environment, "capture:"+captureID)
	if err != nil {
		return err
	}
	changes, err := e.diff(ctx, baseline.SnapshotID, summary.SnapshotID, false)
	if err != nil {
		return err
	}
	if err := validateChanges(changes, captureConfig); err != nil {
		return err
	}
	requirements, err := storageRequirements(changes)
	if err != nil {
		return err
	}
	consistency := "stopped-systemd-writers"
	if frozen {
		consistency = "stopped-systemd-writers+frozen-user-slice"
	}
	manifest := Manifest{
		Schema: schemaVersion, CaptureID: captureID, EnvironmentID: common.environment,
		CreatedAt: time.Now().UTC(), BaselineSnapshotID: baseline.SnapshotID,
		CaptureSnapshotID: summary.SnapshotID, EngineCommit: engineCommit, Config: captureConfig,
		BaselineSystem: baseline.System, CapturedSystem: system, BaselineHost: baseline.Host, SourceHost: host,
		Changes: changes, ServiceIntents: workloadServiceIntents(services, baseline.Services, captureConfig),
		AccountChanges: accountChanges(baseline.Accounts, accounts), PackageChanges: packageDelta,
		TextFileChanges:     textFileChanges(baseline.ReconciledFiles, reconciled),
		StorageRequirements: requirements,
		BaselineFirewall:    baseline.Firewall, CapturedFirewall: firewall,
		SysctlChanges:      sysctlChanges(baseline.Sysctls, sysctls),
		KernelModulesAdded: kernelModulesAdded,
		BaselineSecurity:   baseline.Security, CapturedSecurity: security,
		ExclusionSetHash: configHash(captureConfig), Consistency: consistency,
		CaptureDataAdded: summary.DataAdded, CaptureDataPacked: summary.DataAddedPacked,
		CaptureFilesNew: summary.FilesNew, CaptureFilesChanged: summary.FilesChanged,
		CaptureDirsNew: summary.DirsNew, CaptureDirsChanged: summary.DirsChanged,
	}
	job.Phase = "commit"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	manifestSnapshot, err := e.backupManifest(ctx, manifest)
	if err != nil {
		return err
	}
	released = true
	if err := releaseQuiesce(stopped, frozen, !leaveStopped); err != nil {
		return err
	}
	leaseReleased = true
	if err := releaseLease(); err != nil {
		return err
	}
	now := time.Now().UTC()
	job.Status, job.Phase, job.SnapshotID, job.FinishedAt = "complete", "complete", summary.SnapshotID, &now
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	return emit(map[string]any{
		"status": "capture_committed", "capture_id": captureID,
		"snapshot_id": summary.SnapshotID, "manifest_snapshot_id": manifestSnapshot,
		"changed_paths": len(changes), "new_stored_bytes": summary.DataAddedPacked,
		"consistency": consistency,
	})
}

func restore(ctx context.Context, common commonFlags, manifestRef string, sourceFenced bool) (returnErr error) {
	if err := validateEnvironmentID(common.environment); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := validateRepositoryEnvironment(); err != nil {
		return err
	}
	if err := ensureStateDir(common.stateDir); err != nil {
		return err
	}
	unlock, err := acquireOperationLock(common.stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	e := engine{bin: common.resticBin, stateDir: common.stateDir}
	if err := checkEngine(ctx, e); err != nil {
		return err
	}
	ctx, e, releaseLease, err := e.acquireRepositoryLease(ctx)
	if err != nil {
		return err
	}
	leaseReleased := false
	defer func() {
		if !leaseReleased {
			returnErr = errors.Join(returnErr, releaseLease())
		}
	}()
	manifest, err := loadManifest(ctx, e, common.environment, manifestRef)
	if err != nil {
		return err
	}
	if manifest.Schema != schemaVersion || manifest.EngineCommit != engineCommit {
		return errors.New("manifest_schema_or_engine_mismatch")
	}
	if manifest.EnvironmentID != common.environment {
		return errors.New("environment_id_mismatch")
	}
	if manifest.ExclusionSetHash != configHash(manifest.Config) {
		return errors.New("manifest_policy_hash_mismatch")
	}
	restoreConfig, err := extendReconcileFiles(manifest.Config, discoverAuthorizedKeys())
	if err != nil {
		return err
	}
	for _, change := range manifest.Changes {
		if !isExcludedPath(change.Path, manifest.Config.Exclude) && isExcludedPath(change.Path, restoreConfig.Exclude) {
			return fmt.Errorf("target_protected_path_conflict: %s", change.Path)
		}
	}
	if manifest.Config.RequireSourceFence && !sourceFenced {
		return errors.New("source_not_fenced: pass --source-fenced only after the VM manager fences or destroys the source")
	}
	targetSystem, err := systemInfo()
	if err != nil {
		return err
	}
	if err := compatibleSystem(manifest.BaselineSystem, targetSystem); err != nil {
		return err
	}
	if err := checkStorageRequirements(manifest.StorageRequirements); err != nil {
		return err
	}
	targetFirewall, err := firewallState(ctx)
	if err != nil {
		return err
	}
	if manifest.CapturedFirewall != manifest.BaselineFirewall && targetFirewall != manifest.BaselineFirewall && targetFirewall != manifest.CapturedFirewall {
		return errors.New("target_firewall_baseline_mismatch")
	}
	targetSysctls, err := sysctlInventory(ctx)
	if err != nil {
		return err
	}
	if err := validateSysctlChanges(manifest.SysctlChanges, targetSysctls); err != nil {
		return err
	}
	targetKernelModules, err := kernelModuleInventory()
	if err != nil {
		return err
	}
	if err := validateKernelModuleAdditions(ctx, manifest.KernelModulesAdded, targetKernelModules); err != nil {
		return err
	}
	targetSecurity, err := securityState(ctx)
	if err != nil {
		return err
	}
	if err := validateTargetSecurity(manifest.BaselineSecurity, manifest.CapturedSecurity, targetSecurity); err != nil {
		return err
	}
	targetAccounts, err := accountInventory()
	if err != nil {
		return err
	}
	if err := validateAccountChanges(manifest.AccountChanges, targetAccounts); err != nil {
		return err
	}
	hostBefore, err := hostIdentity(ctx)
	if err != nil {
		return err
	}
	jobPath := filepath.Join(common.stateDir, "jobs", "restore-"+manifest.CaptureID+".json")
	job := Job{ID: "restore-" + manifest.CaptureID, Kind: "restore", Status: "running", Phase: "preflight", StartedAt: time.Now().UTC(), CaptureID: manifest.CaptureID, SnapshotID: manifest.CaptureSnapshotID, TargetHostBefore: hostBefore}
	resuming := false
	var previous Job
	if readJSON(jobPath, &previous) == nil && previous.CaptureID == manifest.CaptureID && previous.Phase != "preflight" && previous.Status != "complete" {
		job, resuming = previous, true
		job.Status, job.Error = "running", ""
	}
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			job.Status, job.Error = "failed", returnErr.Error()
			_ = writeJSONAtomic(jobPath, job, 0600)
		}
	}()
	currentServices, err := serviceIntents(ctx)
	if err != nil {
		return err
	}
	stopped, frozen, err := quiesceSystem(ctx, currentServices, restoreConfig)
	if err != nil {
		return err
	}
	mutated := false
	released := false
	defer func() {
		if !released {
			returnErr = errors.Join(returnErr, releaseQuiesce(stopped, frozen, returnErr != nil && !mutated))
		}
	}()
	syscall.Sync()
	baselinePath := filepath.Join(common.stateDir, "baseline.json")
	baselineCandidatePath := filepath.Join(common.stateDir, "restore-baseline-"+manifest.CaptureID+".json")
	var restoredBaseline Baseline
	if resuming {
		if err := readJSON(baselineCandidatePath, &restoredBaseline); err != nil {
			return fmt.Errorf("load restore baseline candidate: %w", err)
		}
	} else {
		targetPackages, err := packageInventory(ctx)
		if err != nil {
			return err
		}
		targetReconciled, err := textFileInventory(restoreConfig.ReconcileFiles)
		if err != nil {
			return err
		}
		restoredBaseline = Baseline{
			Schema: schemaVersion, EnvironmentID: common.environment, CreatedAt: time.Now().UTC(),
			SnapshotID: manifest.BaselineSnapshotID, EngineCommit: engineCommit, Config: restoreConfig,
			System: targetSystem, Host: hostBefore, Services: currentServices, Packages: targetPackages,
			Accounts: targetAccounts, ReconciledFiles: targetReconciled, Firewall: targetFirewall, Sysctls: targetSysctls,
			KernelModules: targetKernelModules, Security: targetSecurity, ExclusionSetHash: configHash(restoreConfig),
		}
		if err := writeJSONAtomic(baselineCandidatePath, restoredBaseline, 0600); err != nil {
			return err
		}
	}
	if !resuming {
		preflight, err := e.backup(ctx, restoreConfig, manifest.BaselineSnapshotID, true,
			"wormhole-preflight", "env:"+common.environment, "capture:"+manifest.CaptureID)
		if err != nil {
			return err
		}
		drift, err := e.diff(ctx, manifest.BaselineSnapshotID, preflight.SnapshotID, true)
		if err != nil {
			return err
		}
		unexpected := unexpectedTargetDrift(drift, manifest.Changes)
		if len(unexpected) != 0 {
			return fmt.Errorf("target_baseline_mismatch: %s", summarizeChanges(unexpected, 12))
		}
	}
	firewallApplied := false
	defer func() {
		if returnErr != nil && firewallApplied {
			_ = applyFirewallState(context.Background(), targetFirewall)
		}
	}()
	var sysctlRollback map[string]string
	defer func() {
		if returnErr != nil && sysctlRollback != nil {
			_ = restoreSysctls(sysctlRollback)
		}
	}()
	var loadedKernelModules []string
	defer func() {
		if returnErr != nil && len(loadedKernelModules) > 0 {
			_ = unloadKernelModules(loadedKernelModules)
		}
	}()
	securityApplied := false
	defer func() {
		if returnErr != nil && securityApplied {
			_ = applySecurityState(context.Background(), targetSecurity)
		}
	}()
	job.Phase = "apply"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	mutated = true
	if err := predeleteTypeChanges(manifest.Changes, restoreConfig); err != nil {
		return err
	}
	paths := restorePathList(manifest.Changes)
	if err := e.restorePaths(ctx, manifest.CaptureSnapshotID, paths, "/", restoreConfig.RestoreVerify); err != nil {
		return err
	}
	if err := applyDeletions(manifest.Changes, restoreConfig); err != nil {
		return err
	}
	if err := applyAccountChanges(manifest.AccountChanges); err != nil {
		return err
	}
	if err := applyTextFileChanges(manifest.TextFileChanges, restoreConfig.ReconcileFiles, manifest.BaselineHost, manifest.SourceHost, hostBefore); err != nil {
		return err
	}
	job.Phase = "verify-files"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	verification, err := e.backup(ctx, restoreConfig, manifest.CaptureSnapshotID, true,
		"wormhole-verification", "env:"+common.environment, "capture:"+manifest.CaptureID)
	if err != nil {
		return err
	}
	remaining, err := e.diff(ctx, manifest.CaptureSnapshotID, verification.SnapshotID, true)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return fmt.Errorf("restore_content_mismatch: %s", summarizeChanges(remaining, 12))
	}
	remaining, err = e.diff(ctx, manifest.CaptureSnapshotID, verification.SnapshotID, false)
	if err != nil {
		return err
	}
	if remaining = changesAtPlannedPaths(remaining, manifest.Changes); len(remaining) != 0 {
		return fmt.Errorf("restore_metadata_mismatch: %s", summarizeChanges(remaining, 12))
	}
	job.VerificationID = verification.SnapshotID
	job.Phase = "activate"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	loadedKernelModules, err = applyKernelModuleAdditions(ctx, manifest.KernelModulesAdded)
	if err != nil {
		return err
	}
	if err := restoreServiceIntents(ctx, manifest.ServiceIntents); err != nil {
		return err
	}
	if manifest.CapturedFirewall != manifest.BaselineFirewall {
		firewallApplied = true
		if err := applyFirewallState(ctx, manifest.CapturedFirewall); err != nil {
			return err
		}
		actualFirewall, err := firewallState(ctx)
		if err != nil {
			return err
		}
		if actualFirewall != manifest.CapturedFirewall {
			return fmt.Errorf("firewall_restore_mismatch: actual=%q", actualFirewall)
		}
	}
	if len(manifest.SysctlChanges) > 0 {
		sysctlRollback, err = applySysctlChanges(ctx, manifest.SysctlChanges)
		if err != nil {
			return err
		}
	}
	if manifest.CapturedSecurity != manifest.BaselineSecurity && targetSecurity != manifest.CapturedSecurity {
		if err := applySecurityState(ctx, manifest.CapturedSecurity); err != nil {
			return err
		}
		securityApplied = true
	}
	job.Phase = "verify-state"
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	if err := verifyAccountChanges(manifest.AccountChanges); err != nil {
		return err
	}
	if err := verifyTextFileChanges(manifest.TextFileChanges, restoreConfig.ReconcileFiles, manifest.BaselineHost, manifest.SourceHost, hostBefore); err != nil {
		return err
	}
	if err := verifyPackageChanges(ctx, manifest.PackageChanges); err != nil {
		return err
	}
	if err := verifyWorkloads(ctx, manifest.ServiceIntents); err != nil {
		return err
	}
	if err := verifySysctlChanges(ctx, manifest.SysctlChanges); err != nil {
		return err
	}
	if err := verifyKernelModuleAdditions(manifest.KernelModulesAdded); err != nil {
		return err
	}
	actualSecurity, err := securityState(ctx)
	if err != nil {
		return err
	}
	if actualSecurity != manifest.CapturedSecurity {
		return errors.New("security_state_restore_mismatch")
	}
	hostAfter, err := hostIdentity(ctx)
	if err != nil {
		return err
	}
	if err := sameHostIdentity(hostBefore, hostAfter); err != nil {
		return err
	}
	if err := commitRestoredBaseline(baselinePath, restoredBaseline); err != nil {
		return err
	}
	syscall.Sync()
	released = true
	if err := releaseQuiesce(stopped, frozen, false); err != nil {
		return err
	}
	leaseReleased = true
	if err := releaseLease(); err != nil {
		return err
	}
	now := time.Now().UTC()
	job.Status, job.Phase, job.FinishedAt, job.TargetHostAfter = "complete", "ready", &now, hostAfter
	if err := writeJSONAtomic(jobPath, job, 0600); err != nil {
		return err
	}
	_ = os.Remove(baselineCandidatePath)
	return emit(map[string]any{
		"status": "ready", "capture_id": manifest.CaptureID,
		"snapshot_id": manifest.CaptureSnapshotID, "verified_snapshot_id": verification.SnapshotID,
		"restored_paths": len(paths), "host_identity_preserved": true,
	})
}

func commitRestoredBaseline(baselinePath string, candidate Baseline) error {
	var existing Baseline
	if err := readJSON(baselinePath, &existing); err == nil {
		if existing.Schema != candidate.Schema || existing.EngineCommit != candidate.EngineCommit || existing.EnvironmentID != candidate.EnvironmentID || existing.SnapshotID != candidate.SnapshotID || existing.ExclusionSetHash != candidate.ExclusionSetHash {
			return errors.New("existing_baseline_conflict")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeJSONAtomic(baselinePath, candidate, 0600)
}

func inspectManifest(ctx context.Context, common commonFlags, ref string) error {
	if err := validateRepositoryEnvironment(); err != nil {
		return err
	}
	e := engine{bin: common.resticBin, stateDir: common.stateDir}
	manifest, err := loadManifest(ctx, e, common.environment, ref)
	if err != nil {
		return err
	}
	return emit(manifest)
}

func inventory(ctx context.Context, common commonFlags) error {
	cfg, err := loadConfig(common.configPath, common.stateDir)
	if err != nil {
		return err
	}
	system, err := systemInfo()
	if err != nil {
		return err
	}
	host, err := hostIdentity(ctx)
	if err != nil {
		return err
	}
	services, err := serviceIntents(ctx)
	if err != nil {
		return err
	}
	packages, err := packageInventory(ctx)
	if err != nil {
		return err
	}
	return emit(map[string]any{
		"system": system, "host": host, "config": cfg,
		"workload_units": workloadServiceIntents(services, nil, cfg),
		"packages":       packages,
	})
}

func showStatus(stateDir, jobID string) error {
	if jobID != "" {
		var job Job
		if err := readJSON(filepath.Join(stateDir, "jobs", filepath.Base(jobID)+".json"), &job); err != nil {
			return err
		}
		return emit(job)
	}
	paths, err := filepath.Glob(filepath.Join(stateDir, "jobs", "*.json"))
	if err != nil {
		return err
	}
	jobs := make([]Job, 0, len(paths))
	for _, path := range paths {
		var job Job
		if readJSON(path, &job) == nil {
			jobs = append(jobs, job)
		}
	}
	slices.SortFunc(jobs, func(a, b Job) int { return b.StartedAt.Compare(a.StartedAt) })
	return emit(jobs)
}

func checkEngine(ctx context.Context, e engine) error {
	if _, err := os.Stat(e.bin); err != nil && strings.ContainsRune(e.bin, filepath.Separator) {
		return err
	}
	out, err := e.run(ctx, nil, false, "help", "restore")
	if err != nil {
		return err
	}
	if !bytesContains(out, "--include-file-raw") {
		return errors.New("restic engine lacks Wormhole exact-path restore extension")
	}
	out, err = e.run(ctx, nil, false, "help", "diff")
	if err != nil {
		return err
	}
	if !bytesContains(out, "--metadata-portable") || !bytesContains(out, "--ignore-file-mtime") {
		return errors.New("restic engine lacks Wormhole portable metadata extension")
	}
	if _, err := e.run(ctx, nil, false, "help", "wormhole-lock"); err != nil {
		return errors.New("restic engine lacks Wormhole workflow lease extension")
	}
	return nil
}

func validateChanges(changes []Change, cfg Config) error {
	for _, change := range changes {
		path := filepath.Clean(change.Path)
		if path == "/" && change.Modifier == "U" && slices.Contains(cfg.Roots, "/") {
			continue
		}
		if !filepath.IsAbs(path) || path == "/" || !withinRoots(path, cfg.Roots) {
			return fmt.Errorf("unsafe change path %q", change.Path)
		}
		if isProtectedPath(path) || isExcludedPath(path, cfg.Exclude) {
			return fmt.Errorf("protected path escaped capture policy: %s", path)
		}
	}
	return nil
}

func restorePathList(changes []Change) []string {
	paths := []string{}
	for _, change := range changes {
		if !strings.Contains(change.Modifier, "-") {
			paths = append(paths, filepath.Clean(change.Path))
		}
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

func unexpectedTargetDrift(drift, planned []Change) []Change {
	owned := map[string]bool{}
	for _, change := range planned {
		owned[filepath.Clean(change.Path)] = true
	}
	unexpected := []Change{}
	for _, change := range drift {
		if !owned[filepath.Clean(change.Path)] {
			unexpected = append(unexpected, change)
		}
	}
	return unexpected
}

func changesAtPlannedPaths(changes, planned []Change) []Change {
	owned := map[string]bool{}
	for _, change := range planned {
		owned[filepath.Clean(change.Path)] = true
	}
	result := []Change{}
	for _, change := range changes {
		if owned[filepath.Clean(change.Path)] {
			result = append(result, change)
		}
	}
	return result
}

func predeleteTypeChanges(changes []Change, cfg Config) error {
	for _, change := range changes {
		if strings.Contains(change.Modifier, "T") {
			if err := safeRemove(change.Path, cfg); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyDeletions(changes []Change, cfg Config) error {
	covered := []string{}
	for _, change := range changes {
		if strings.Contains(change.Modifier, "-") || strings.Contains(change.Modifier, "T") {
			covered = append(covered, filepath.Clean(change.Path))
		}
	}
	slices.SortFunc(covered, func(a, b string) int {
		if depth := strings.Count(a, "/") - strings.Count(b, "/"); depth != 0 {
			return depth
		}
		return strings.Compare(a, b)
	})
	paths := []string{}
	for _, change := range changes {
		if strings.Contains(change.Modifier, "-") {
			path := filepath.Clean(change.Path)
			shadowed := false
			for _, parent := range covered {
				if parent == path {
					break
				}
				if strings.HasPrefix(path, parent+string(filepath.Separator)) {
					shadowed = true
					break
				}
			}
			if !shadowed {
				paths = append(paths, path)
			}
		}
	}
	for _, path := range paths {
		if err := safeRemove(path, cfg); err != nil {
			return err
		}
	}
	return nil
}

func safeRemove(path string, cfg Config) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == "/" || !withinRoots(path, cfg.Roots) || isProtectedPath(path) || isExcludedPath(path, cfg.Exclude) {
		return fmt.Errorf("refusing to delete unsafe path %q", path)
	}
	for parent := filepath.Dir(path); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to delete through symlinked parent %q", parent)
		}
	}
	return os.RemoveAll(path)
}

func isExcludedPath(path string, patterns []string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(pattern)
		if strings.HasPrefix(pattern, "**/") && strings.HasSuffix(path, strings.TrimPrefix(pattern, "**")) {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			base := strings.TrimSuffix(pattern, "/**")
			if path == base || strings.HasPrefix(path, base+"/") {
				return true
			}
			continue
		}
		if filepath.IsAbs(pattern) && !strings.ContainsAny(pattern, "*?[") && (path == pattern || strings.HasPrefix(path, pattern+"/")) {
			return true
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

func withinRoots(path string, roots []string) bool {
	for _, root := range roots {
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isProtectedPath(path string) bool {
	if strings.HasPrefix(path, "/etc/NetworkManager/system-connections/cloud-init-") || strings.HasPrefix(path, "/etc/systemd/network/10-cloud-init-") {
		return true
	}
	protected := []string{
		"/proc", "/sys", "/dev", "/run", "/etc/machine-id", "/var/lib/dbus/machine-id",
		"/etc/hostname", "/etc/hosts", "/var/lib/cloud", "/etc/cloud", "/boot", "/lib/modules", "/usr/lib/modules",
		"/etc/netplan/50-cloud-init.yaml", "/etc/network/interfaces.d/50-cloud-init",
		"/etc/NetworkManager/system-connections/cloud-init-eth0.nmconnection", "/etc/systemd/network/10-cloud-init-eth0.network",
		"/etc/sysconfig/network-scripts/ifcfg-eth0",
		"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
	}
	for _, root := range protected {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return strings.HasPrefix(path, "/etc/ssh/ssh_host_")
}

func freezeUserSlice(ctx context.Context) bool {
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	if strings.Contains(string(cgroup), "user.slice") {
		return false
	}
	_, err := commandOutput(ctx, "systemctl", "freeze", "user.slice")
	return err == nil
}

func thawUserSlice(ctx context.Context) error {
	_, err := commandOutput(ctx, "systemctl", "thaw", "user.slice")
	return err
}

func newID() string {
	random := make([]byte, 6)
	_, _ = rand.Read(random)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random)
}

func summarizeChanges(changes []Change, limit int) string {
	parts := make([]string, 0, min(len(changes), limit))
	for i, change := range changes {
		if i == limit {
			break
		}
		parts = append(parts, change.Modifier+" "+change.Path)
	}
	if len(changes) > limit {
		parts = append(parts, fmt.Sprintf("... and %d more", len(changes)-limit))
	}
	return strings.Join(parts, ", ")
}

func bytesContains(data []byte, value string) bool { return strings.Contains(string(data), value) }

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("wormhole baseline, capture, and restore require root")
	}
	return nil
}

func emit(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
