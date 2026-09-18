# Validation and tested systems

Wormhole's tests are behavior-based. An application or distribution earns no
special restore path; a fixture either proves the generic state model or exposes
a boundary that applies to every workload.

## Evidence levels

- **Latest binary:** completed using the exact final compatibility-test binary.
- **Current line:** completed using the current `wormhole.18` engine stamp.
- **Earlier development build:** completed before the final durability barrier
  or later exclusion refinements; useful compatibility evidence, but not a
  current-build qualification.
- **Implemented:** code and local tests exist, but the named cloud image has not
  completed the full destructive lifecycle on the current build.

All cloud results below were run on Hetzner Cloud x86_64 VMs with
S3-compatible object storage from 2026-09-16 through 2026-09-18.

## Completed OS coverage

| OS | Evidence | Completed scenarios |
| --- | --- | --- |
| Ubuntu 22.04 LTS, 24.04 LTS, 26.04 | Current line | Three-VM lifecycle; Ubuntu 24.04 additionally covered nginx, SQLite, Python, Node, Go, PostgreSQL with a live writer, Docker, ext4 storage, corruption, repository locking, and forced interruption/retry |
| Debian 12, 13 | Current line | Three-VM generic lifecycle; metadata, package, account, service, firewall, sysctl, module, reboot, continued-write, and second-restore validation |
| Fedora 43, 44 | Current line | Three-VM generic lifecycle; Fedora 44 additionally covered SELinux Permissive→Enforcing runtime and persistent configuration |
| AlmaLinux 8 | Latest binary | Three-VM generic lifecycle through second restore and reboot |
| AlmaLinux 9, 10 | Current line | Three-VM generic lifecycle; AlmaLinux 10 additionally covered an attached XFS corpus |
| Rocky Linux 8, 9 | Latest binary | Three-VM generic lifecycle through second restore and reboot |
| Rocky Linux 10 | Current line | Three-VM generic lifecycle through second restore and reboot |
| CentOS Stream 9 | Latest binary | Three-VM generic lifecycle through second restore and reboot |
| CentOS Stream 10 | Current line | Three-VM generic lifecycle through second restore and reboot |
| openSUSE 16 | Current line | Three-VM generic lifecycle and cloud-init `/etc/hosts` persistence across both reboots |

The latest-binary rows used the same static Wormhole artifact in one parallel
run. Across the full matrix, all 16 advertised images completed the lifecycle.

Package inventory and mutation paths exist for dpkg/APT, RPM/DNF, and
RPM/Zypper. That implementation coverage must not be confused with release-by-
release qualification.

## Scenarios exercised

The cloud harness has exercised:

- source deletion before target creation;
- target hostname, machine ID, addresses, routes, SSH host keys, and provider
  access remaining target-owned;
- content and metadata changes, hard links, symlinks, sparse files, FIFOs,
  newline-containing names, deletion, and file/directory type transitions;
- ACLs, xattrs, Linux file capabilities, users, SSH authorized keys,
  `/etc/hosts`, cron, package installation, and package removal;
- active, inactive, disabled, masked, socket, timer, path, service, and
  lab-created tmpfs mount units;
- nginx content, SQLite state, runtime nftables rules, persistent/runtime
  sysctls, and a source-added dummy module;
- Docker, Python, Node, Go, PostgreSQL, continuous writers, and 5,000-file
  attached-volume corpora;
- ext4 and XFS mounted-volume restore plus missing mount, wrong filesystem, and
  insufficient-space rejection;
- reboot after restore, independent source/target oracles, continued writes,
  recapture, and restore onto a third VM;
- missing source fence, unrelated target drift, and bad repository password
  failing before mutation;
- a live repository lease blocking restore;
- deliberate encrypted-pack corruption failing without a complete status, then
  successful recovery after repair;
- forced reboot during capture and restore followed by checkpointed retry.

The destructive interruption, live-lock, repository-corruption, full
application, and SELinux profiles completed on the current `.18` line. The
latest affected-release rerun exercised the final static build and compatibility
policy without harness workarounds.

## Local tests

Run the application tests and focused pinned-Restic tests with:

```sh
make test
```

The Go suite covers manifest selection, policy boundaries, account and
mixed-file reconciliation, service intent normalization, firewall/sysctl/module
logic, SELinux transition validation, path safety, compatibility checks, and
workflow helpers. The Restic tests cover exact raw-path inclusion and portable
metadata comparison.

## Hetzner end-to-end harness

The harness creates and destroys real servers, volumes, and a temporary SSH
key. It incurs provider and object-storage charges. Use a dedicated account or
project and verify cleanup after interruption.

Prepare credentials:

```sh
cp tests/hetzner.env.example tests/hetzner.env
chmod 600 tests/hetzner.env
# Fill in Hetzner and S3-compatible credentials.
```

Run the configured matrix:

```sh
./tests/hetzner-e2e.sh ./tests/hetzner.env
```

Useful environment overrides include:

```sh
TEST_IMAGES_OVERRIDE='ubuntu-24.04 fedora-44'
CONTAINER_TEST_IMAGE='ubuntu-24.04'
ROBUST_TEST_IMAGE_OVERRIDE='ubuntu-24.04'
VOLUME_EXT4_IMAGE='ubuntu-24.04'
VOLUME_XFS_IMAGE='alma-10'
SELINUX_TEST_IMAGE='fedora-44'
INTERRUPTION_TEST_IMAGE='ubuntu-24.04'
CORRUPTION_TEST_IMAGE='ubuntu-24.04'
LOCK_TEST_IMAGE='ubuntu-24.04'
```

The harness records JSON results and independent oracle output under
`artifacts/hetzner/`, which is intentionally gitignored because it can be large
and environment-specific. Its cleanup trap deletes the current server, attached
volume, temporary key, and repairs a deliberately corrupted repository object.

## Remaining qualification gaps

- Repeat the full 16-image matrix and extended destructive profiles on a tagged
  release candidate.
- Run the full lifecycle on a second cloud provider.
- Add explicit AppArmor behavior or document it permanently out of scope.
- Exercise more storage topologies through a defined VM-manager contract,
  including LVM and encrypted volumes.
- Qualify distributed/orchestrated workloads and writers outside systemd and
  `user.slice` without adding product-specific capture logic.
- Exercise workload data that embeds source host identity and document which
  classes are portable.

Release qualification requires repeatable source destruction, fresh-target
restore, independent validation, continued writes, recapture, second restore,
and preserved replacement-host identity for every claimed platform.
