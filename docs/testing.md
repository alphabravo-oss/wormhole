# Validation and tested systems

Wormhole's tests are behavior-based. An application or distribution earns no
special restore path; a fixture either proves the generic state model or exposes
a boundary that applies to every workload.

## Evidence levels

- **Current build:** completed using the current `wormhole.18` engine stamp.
- **Earlier development build:** completed before the final durability barrier
  or later exclusion refinements; useful compatibility evidence, but not a
  current-build qualification.
- **Implemented:** code and local tests exist, but the named cloud image has not
  completed the full destructive lifecycle on the current build.

All cloud results below were run on Hetzner Cloud x86_64 VMs with
S3-compatible object storage on 2026-09-17.

## Completed OS coverage

| OS | Evidence | Completed scenarios |
| --- | --- | --- |
| Ubuntu 24.04 LTS | Current build | Three-VM lifecycle; nginx; SQLite; Python venv and locally installed package; Node/npm local dependency; compiled Go program; PostgreSQL with active writer and exact logical-data checksum; Docker image, running container, named volume, and writable layer; ext4 attached volume; metadata edge cases; reboot; continued writes; recapture; second fresh restore |
| Fedora 44 | Current build | Three-VM generic lifecycle; package/account/service/firewall/sysctl/module fixtures; SELinux Permissive→Enforcing runtime and persistent configuration; reboot; continued writes; recapture; second fresh restore |
| Debian 12 | Earlier development build | Fresh-target generic lifecycle; SQLite and continuous writer; metadata, package, account, and service state; source-fence and target-drift rejection; continued-write validation and recapture |
| Rocky Linux 10 | Earlier development build | Fresh-target generic lifecycle; SQLite and continuous writer; metadata, package, account, and service state; source-fence and target-drift rejection; continued-write validation and recapture |
| AlmaLinux 10 | Earlier development build | Three-VM generic lifecycle and attached XFS corpus |
| CentOS Stream 10 | Earlier development build | Three-VM generic lifecycle |
| openSUSE 16 | Earlier development build | Three-VM generic lifecycle |

The live Hetzner catalog also exposed AlmaLinux 8/9, CentOS Stream 9, Debian 13,
Fedora 43, Rocky 8/9, and Ubuntu 22.04/26.04. A final all-version run was started
and intentionally stopped: AlmaLinux 8, CentOS Stream 9, and Fedora 43 were
provisioned but did not complete, and the other listed images were not reached.

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

The destructive interruption, live-lock, and repository-corruption profile
completed on `wormhole.17`. The current `.18` change adds only a successful-
restore filesystem durability barrier; the full application and SELinux
profiles completed on `.18`.

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

- Complete the current-build matrix for every claimed OS version.
- Repeat destructive interruption/corruption/lease cases on the final build.
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
