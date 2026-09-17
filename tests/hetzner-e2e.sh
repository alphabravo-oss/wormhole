#!/usr/bin/env bash
set -Eeuo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

[[ $# == 1 ]] || die "usage: $0 /path/to/hetzner.env"
secrets=$1
[[ -f $secrets ]] || die "credential file not found: $secrets"
mode=$(stat -c '%a' "$secrets")
(( (8#$mode & 077) == 0 )) || die "credential file must not be group/world accessible (chmod 600 $secrets)"
set -a
# shellcheck disable=SC1090
. "$secrets"
set +a

required=(HCLOUD_TOKEN S3_ENDPOINT S3_BUCKET AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY RESTIC_PASSWORD)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || die "$name is required in $secrets"
done
for command in curl jq ssh scp ssh-keygen go; do
  command -v "$command" >/dev/null || die "$command is required"
done

HCLOUD_LOCATION=${HCLOUD_LOCATION:-fsn1}
HCLOUD_SERVER_TYPE=${HCLOUD_SERVER_TYPE:-cx23}
TEST_IMAGES=${TEST_IMAGES_OVERRIDE:-${TEST_IMAGES:-"ubuntu-24.04 debian-12"}}
CONTAINER_TEST_IMAGE=${CONTAINER_TEST_IMAGE:-ubuntu-24.04}
ROBUST_TEST_IMAGE=${ROBUST_TEST_IMAGE_OVERRIDE:-${ROBUST_TEST_IMAGE:-}}
REBOOT_AFTER_RESTORE=${REBOOT_AFTER_RESTORE:-1}
VOLUME_EXT4_IMAGE=${VOLUME_EXT4_IMAGE:-}
VOLUME_XFS_IMAGE=${VOLUME_XFS_IMAGE:-}
SELINUX_TEST_IMAGE=${SELINUX_TEST_IMAGE:-}
INTERRUPTION_TEST_IMAGE=${INTERRUPTION_TEST_IMAGE:-}
CORRUPTION_TEST_IMAGE=${CORRUPTION_TEST_IMAGE:-}
LOCK_TEST_IMAGE=${LOCK_TEST_IMAGE:-}
WORMHOLE_S3_PREFIX=${WORMHOLE_S3_PREFIX:-wormhole-e2e}
S3_ENDPOINT=${S3_ENDPOINT#https://}
S3_ENDPOINT=${S3_ENDPOINT%/}
case $HCLOUD_LOCATION in
  fsn1|nbg1|hel1) ;;
  *) die "HCLOUD_LOCATION must be a European Hetzner location: fsn1, nbg1, or hel1" ;;
esac
if [[ $S3_ENDPOINT == *.your-objectstorage.com && ${S3_ENDPOINT%%.*} != "$HCLOUD_LOCATION" ]]; then
  die "S3_ENDPOINT and HCLOUD_LOCATION must use the same European location"
fi
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-${S3_ENDPOINT%%.*}}
run_id=$(date -u +%Y%m%d%H%M%S)-$RANDOM
root=$(cd "$(dirname "$0")/.." && pwd)
report_dir="$root/artifacts/hetzner/$run_id"
scratch=$(mktemp -d)
mkdir -p "$report_dir"
key="$scratch/id_ed25519"
known_hosts="$scratch/known_hosts"
current_server=
current_ip=
current_volume=
current_volume_device=
ssh_key_id=
corrupted_url=
corrupted_backup=

api() {
  local method=$1 path=$2 body=${3:-}
  local args=(--silent --show-error --fail-with-body -X "$method"
    -H "Authorization: Bearer $HCLOUD_TOKEN"
    -H 'Content-Type: application/json')
  [[ -z $body ]] || args+=(--data "$body")
  curl "${args[@]}" "https://api.hetzner.cloud/v1$path"
}

api_status() {
  local path=$1
  curl --silent --output /dev/null --write-out '%{http_code}' \
    -H "Authorization: Bearer $HCLOUD_TOKEN" "https://api.hetzner.cloud/v1$path"
}

s3_curl() {
  local method=$1 url=$2 file=${3:-} args
  args=(--silent --show-error --fail --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"
    --aws-sigv4 "aws:amz:$AWS_DEFAULT_REGION:s3" -X "$method")
  [[ -z ${AWS_SESSION_TOKEN:-} ]] || args+=(-H "x-amz-security-token: $AWS_SESSION_TOKEN")
  case $method in
    GET) args+=(--output "$file") ;;
    PUT) args+=(--upload-file "$file") ;;
  esac
  curl "${args[@]}" "$url"
}

repair_corruption() {
  [[ -n $corrupted_url && -s $corrupted_backup ]] || return 0
  log "repairing deliberately corrupted repository pack"
  s3_curl PUT "$corrupted_url" "$corrupted_backup"
  corrupted_url=
  corrupted_backup=
}

delete_volume() {
  local id=${1:-}
  [[ -n $id ]] || return 0
  log "deleting volume $id"
  local status
  for _ in {1..60}; do
    status=$(api_status "/volumes/$id")
    [[ $status == 404 ]] && return
    api DELETE "/volumes/$id" >/dev/null 2>&1 || true
    sleep 2
  done
  return 1
}

delete_server() {
  local id=${1:-}
  [[ -n $id ]] || return 0
  log "deleting server $id"
  local status
  status=$(api_status "/servers/$id")
  if [[ $status != 404 ]]; then
    api DELETE "/servers/$id" >/dev/null
    for _ in {1..60}; do
      status=$(api_status "/servers/$id")
      [[ $status == 404 ]] && break
      sleep 2
    done
    [[ $status == 404 ]] || { log "server $id still exists after delete request"; return 1; }
  fi
  if [[ $current_server == "$id" ]]; then
    [[ -z $current_ip ]] || ssh-keygen -q -R "$current_ip" -f "$known_hosts" >/dev/null 2>&1 || true
    current_server=
    current_ip=
    delete_volume "$current_volume"
    current_volume=
    current_volume_device=
  fi
}

cleanup() {
  local status=$?
  set +e
  repair_corruption
  if (( status != 0 )) && [[ -n $current_ip ]]; then
    remote 'systemctl --failed --no-legend --no-pager; journalctl -b --no-pager -n 500' >"$report_dir/failure-journal.txt" 2>&1 || true
  fi
  delete_server "$current_server"
  delete_volume "$current_volume"
  if [[ -n $ssh_key_id ]]; then
    log "deleting temporary SSH key $ssh_key_id"
    api DELETE "/ssh_keys/$ssh_key_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch"
  if (( status == 0 )); then
    log "PASS: reports are in $report_dir"
  else
    log "FAIL: reports are in $report_dir"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$known_hosts")
# Commands are fixed by this harness; variable data passed here is numeric or hashed fixture output.
# shellcheck disable=SC2029
remote() {
  if (( $# == 1 )); then
    ssh "${ssh_opts[@]}" "root@$current_ip" "$1"
    return
  fi
  local remote_command
  printf -v remote_command '%q ' "$@"
  ssh "${ssh_opts[@]}" "root@$current_ip" "${remote_command% }"
}
remote_bounded() {
  ssh "${ssh_opts[@]}" -o ServerAliveInterval=5 -o ServerAliveCountMax=6 "root@$current_ip" "$1"
}
copy_to() { scp -O "${ssh_opts[@]}" "$1" "root@$current_ip:$2"; }

wait_for_server() {
  local status
  for _ in {1..90}; do
    status=$(api GET "/servers/$current_server" | jq -r '.server.status')
    [[ $status == running ]] && return
    sleep 2
  done
  die "server $current_server did not enter running state"
}

wait_for_ssh() {
  for _ in {1..90}; do
    if remote 'cloud-init status --wait >/dev/null 2>&1 || true; test -r /etc/os-release' >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  die "SSH did not become ready at $current_ip"
}

wait_for_boot_change() {
  local before=$1 after=
  for _ in {1..120}; do
    after=$(remote 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    [[ -n $after && $after != "$before" ]] && return
    sleep 2
  done
  die "server $current_server did not complete a reboot"
}

reboot_and_wait() {
  local before
  before=$(remote 'cat /proc/sys/kernel/random/boot_id')
  remote 'systemctl reboot' >/dev/null 2>&1 || true
  wait_for_boot_change "$before"
}

mount_current_volume() {
  [[ -n $current_volume_device ]] || return 0
  local device=$current_volume_device
  remote "install -d /srv/wormhole-volume; mountpoint -q /srv/wormhole-volume || mount '$device' /srv/wormhole-volume"
}

create_volume() {
  local image=$1 role=$2 filesystem=$3 body response
  body=$(jq -n --arg name "wh-${run_id}-${image//[^a-zA-Z0-9]/-}-$role" \
    --arg format "$filesystem" --arg run "$run_id" --argjson server "$current_server" \
    '{name:$name,size:10,server:$server,automount:false,format:$format,labels:{purpose:"wormhole-e2e",run:$run}}')
  log "creating $filesystem volume for $image $role"
  response=$(api POST /volumes "$body")
  printf '%s\n' "$response" >"$report_dir/$image-$role-volume.json"
  current_volume=$(jq -er '.volume.id' <<<"$response")
  current_volume_device=$(jq -er '.volume.linux_device' <<<"$response")
  for _ in {1..60}; do
    if remote "test -b '$current_volume_device'" 2>/dev/null; then
      mount_current_volume
      return
    fi
    sleep 2
  done
  die "volume $current_volume did not appear on server $current_server"
}

create_server() {
  local image=$1 role=$2 name
  name="wh-${run_id}-${image//[^a-zA-Z0-9]/-}-$role"
  local body response
  body=$(jq -n \
    --arg name "$name" --arg image "$image" --arg type "$HCLOUD_SERVER_TYPE" \
    --arg location "$HCLOUD_LOCATION" --arg run "$run_id" --argjson key "$ssh_key_id" \
    '{name:$name,image:$image,server_type:$type,location:$location,ssh_keys:[$key],start_after_create:true,labels:{purpose:"wormhole-e2e",run:$run}}')
  log "creating $image $role server"
  response=$(api POST /servers "$body")
  printf '%s\n' "$response" >"$report_dir/$image-$role-create.json"
  current_server=$(jq -er '.server.id' <<<"$response")
  current_ip=$(jq -er '.server.public_net.ipv4.ip' <<<"$response")
  wait_for_server
  wait_for_ssh
  if [[ $image == "$VOLUME_EXT4_IMAGE" ]]; then
    create_volume "$image" "$role" ext4
  elif [[ $image == "$VOLUME_XFS_IMAGE" ]]; then
    create_volume "$image" "$role" xfs
  fi
  log "$image $role is ready at $current_ip"
}

write_remote_env() {
  local environment=$1 repository=$2 file="$scratch/remote.env"
  {
    printf 'WORMHOLE_ENVIRONMENT_ID=%q\n' "$environment"
    printf 'RESTIC_REPOSITORY=%q\n' "$repository"
    printf 'RESTIC_PASSWORD=%q\n' "$RESTIC_PASSWORD"
    printf 'AWS_ACCESS_KEY_ID=%q\n' "$AWS_ACCESS_KEY_ID"
    printf 'AWS_SECRET_ACCESS_KEY=%q\n' "$AWS_SECRET_ACCESS_KEY"
    printf 'AWS_DEFAULT_REGION=%q\n' "$AWS_DEFAULT_REGION"
    if [[ -n ${AWS_SESSION_TOKEN:-} ]]; then
      printf 'AWS_SESSION_TOKEN=%q\n' "$AWS_SESSION_TOKEN"
    fi
  } >"$file"
  chmod 600 "$file"
  copy_to "$file" /run/wormhole.env
  remote 'chmod 600 /run/wormhole.env'
}

install_wormhole() {
  copy_to "$root/bin/wormhole" /tmp/wormhole
  copy_to "$root/bin/restic" /tmp/restic
  remote 'install -m 0755 /tmp/wormhole /usr/local/bin/wormhole; install -m 0755 /tmp/restic /usr/local/bin/restic; rm -f /tmp/wormhole /tmp/restic'
}

install_crash_wrapper() {
  local command=$1
  remote bash -se -- "$command" <<'REMOTE'
set -Eeuo pipefail
command=$1
mv /usr/local/bin/restic /usr/local/bin/restic.real
cat >/usr/local/bin/restic <<'SCRIPT'
#!/bin/bash
set -Eeuo pipefail
mode=$(cat /run/wormhole-crash-on 2>/dev/null || true)
for argument in "$@"; do
  if [[ $argument == help ]]; then
    exec /usr/local/bin/restic.real "$@"
  fi
done
for argument in "$@"; do
  if [[ -n $mode && $argument == "$mode" ]]; then
    rm -f /run/wormhole-crash-on
    systemctl reboot --force --force
    sleep 300
  fi
done
exec /usr/local/bin/restic.real "$@"
SCRIPT
chmod 0755 /usr/local/bin/restic
printf '%s\n' "$command" >/run/wormhole-crash-on
REMOTE
}

remove_crash_wrapper() {
  remote 'test ! -e /usr/local/bin/restic.real || mv -f /usr/local/bin/restic.real /usr/local/bin/restic; rm -f /run/wormhole-crash-on'
}

corrupt_capture_pack() {
  local image=$1 pack
  pack=$(comm -13 "$report_dir/$image-baseline-packs.txt" "$report_dir/$image-capture-packs.txt" | head -n 1)
  [[ $pack =~ ^[0-9a-f]{64}$ ]] || die "$image capture created no selectable repository pack"
  corrupted_url="https://${S3_ENDPOINT}/${S3_BUCKET}/${WORMHOLE_S3_PREFIX}/${run_id}/${image}/data/${pack:0:2}/$pack"
  corrupted_backup="$scratch/$pack"
  s3_curl GET "$corrupted_url" "$corrupted_backup"
  [[ -s $corrupted_backup ]] || die "$image selected repository pack was empty"
  s3_curl PUT "$corrupted_url" /dev/null
}

seed_base() {
  remote 'bash -se' <<'REMOTE'
set -Eeuo pipefail
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_SUSPEND=1
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends tree
elif command -v dnf >/dev/null; then
  dnf install -y -q tree
elif command -v zypper >/dev/null; then
  zypper --non-interactive install tree
else
  printf 'unsupported fixture package manager\n' >&2
  exit 1
fi
install -d -m 0755 /opt/wormhole-fixture/type-change /var/lib/wormhole-fixture
printf 'baseline\n' >/opt/wormhole-fixture/modified.txt
printf 'remove-me\n' >/opt/wormhole-fixture/delete-me.txt
printf 'old-directory-member\n' >/opt/wormhole-fixture/type-change/member.txt
chmod 0644 /opt/wormhole-fixture/modified.txt
touch -d @1700000000 /opt/wormhole-fixture/modified.txt /opt/wormhole-fixture/delete-me.txt /opt/wormhole-fixture/type-change/member.txt
if mountpoint -q /srv/wormhole-volume; then
  install -d /srv/wormhole-volume/lab
  printf 'baseline-volume-state\n' >/srv/wormhole-volume/lab/baseline.txt
fi
sync
REMOTE
}

create_compatible_target() {
  local image=$1 role=$2 expected_kernel=$3 actual_kernel
  for attempt in {1..5}; do
    create_server "$image" "$role"
    actual_kernel=$(remote 'uname -r')
    if [[ $actual_kernel == "$expected_kernel" ]]; then
      install_wormhole
      write_remote_env "$environment" "$repository"
      seed_base
      remote 'install -d -m 0700 /var/lib/wormhole; cp /etc/hosts /var/lib/wormhole/target-hosts-before'
      return
    fi
    log "$image $role candidate $attempt has kernel $actual_kernel, need $expected_kernel; recreating"
    delete_server "$current_server"
  done
  die "$image could not provision a $role with captured kernel $expected_kernel after 5 attempts"
}

mutate_source() {
  local container_test=$1 selinux_test=$2
  remote bash -se -- "$container_test" "$selinux_test" <<'REMOTE'
set -Eeuo pipefail
container_test=$1 selinux_test=$2
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_SUSPEND=1
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends acl attr libcap2-bin nftables nginx sqlite3
  apt-get purge -y -qq tree
elif command -v dnf >/dev/null; then
  dnf install -y -q acl attr libcap nftables nginx sqlite
  dnf remove -y -q tree
elif command -v zypper >/dev/null; then
  zypper --non-interactive install acl attr libcap-progs nftables nginx sqlite3
  zypper --non-interactive remove tree
elif command -v pacman >/dev/null; then
  pacman -Sy --noconfirm acl attr libcap nftables nginx sqlite
  pacman -R --noconfirm tree
else
  printf 'unsupported fixture package manager\n' >&2
  exit 1
fi

if [[ $container_test == 1 ]]; then
  command -v apt-get >/dev/null || { printf 'container fixture currently requires an apt image\n' >&2; exit 1; }
  apt-get install -y -qq --no-install-recommends busybox-static docker.io
  install -d /opt/wormhole-container-build
  cp /bin/busybox /opt/wormhole-container-build/busybox
  printf 'container state survived\n' >/opt/wormhole-container-build/index.html
  cat >/opt/wormhole-container-build/Dockerfile <<'DOCKERFILE'
FROM scratch
COPY busybox /busybox
COPY index.html /www/index.html
ENTRYPOINT ["/busybox", "httpd", "-f", "-p", "8080", "-h", "/www"]
DOCKERFILE
  systemctl enable --now docker.service
  docker build -q -t wormhole-local:1 /opt/wormhole-container-build >/dev/null
  docker volume create wormhole-course-data >/dev/null
  docker run --rm --entrypoint /busybox -v wormhole-course-data:/data wormhole-local:1 sh -c 'printf volume-state >/data/value'
  docker run -d --name wormhole-course --restart unless-stopped -p 18081:8080 -v wormhole-course-data:/data wormhole-local:1 >/dev/null
  docker exec wormhole-course /busybox sh -c 'printf writable-layer >/layer-state'
fi

printf 'changed\n' >/opt/wormhole-fixture/modified.txt
chmod 0640 /opt/wormhole-fixture/modified.txt
rm /opt/wormhole-fixture/delete-me.txt
rm -rf /opt/wormhole-fixture/type-change
ln -s /etc/os-release /opt/wormhole-fixture/type-change
printf 'brackets and newline\n' >$'/opt/wormhole-fixture/name[1]\nsecond-line'
setfattr -n user.wormhole -v preserved /opt/wormhole-fixture/modified.txt
printf '192.0.2.123 wormhole-course.local\n' >>/etc/hosts
awk '{$NF="wormhole-course-key"; print; exit}' /root/.ssh/authorized_keys >>/root/.ssh/authorized_keys
nft add table inet wormhole_course
cat >/etc/systemd/system/wormhole-firewall.service <<'UNIT'
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft list table inet wormhole_course >/dev/null 2>&1 || /usr/sbin/nft add table inet wormhole_course'
ExecStop=/bin/sh -c '/usr/sbin/nft delete table inet wormhole_course >/dev/null 2>&1 || :'
[Install]
WantedBy=multi-user.target
UNIT

useradd --create-home --uid 23123 --shell /bin/bash wormhole-lab
printf 'account-data\n' >/home/wormhole-lab/state.txt
install -d -m 0700 /home/wormhole-lab/.ssh
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabCreatedAfterBaseline wormhole-lab\n' >/home/wormhole-lab/.ssh/authorized_keys
chmod 0600 /home/wormhole-lab/.ssh/authorized_keys
chown -R wormhole-lab:wormhole-lab /home/wormhole-lab
setfacl -m u:wormhole-lab:r /opt/wormhole-fixture/modified.txt

printf 'hard-linked-data\n' >/opt/wormhole-fixture/hardlink-a
ln /opt/wormhole-fixture/hardlink-a /opt/wormhole-fixture/hardlink-b
mkfifo /opt/wormhole-fixture/course.fifo
truncate -s 67108864 /opt/wormhole-fixture/sparse.img
printf 'sparse-tail' | dd of=/opt/wormhole-fixture/sparse.img bs=1 seek=67108853 conv=notrunc status=none
cp /bin/true /opt/wormhole-fixture/capability-binary
setcap cap_net_bind_service=ep /opt/wormhole-fixture/capability-binary

if mountpoint -q /srv/wormhole-volume; then
  rm /srv/wormhole-volume/lab/baseline.txt
  install -d /srv/wormhole-volume/lab/corpus
  printf 'attached-volume-state\n' >/srv/wormhole-volume/lab/state.txt
  for number in $(seq 1 5000); do
    printf 'volume-file-%s\n' "$number" >"/srv/wormhole-volume/lab/corpus/$number"
  done
fi

install -d /etc/cron.d
cat >/etc/cron.d/wormhole-course <<'CRON'
17 4 * * * root test -f /opt/wormhole-fixture/modified.txt
CRON
cat >/etc/sysctl.d/99-wormhole-course.conf <<'SYSCTL'
vm.swappiness = 17
SYSCTL
sysctl -q -w vm.swappiness=17
printf 'dummy\n' >/etc/modules-load.d/wormhole-course.conf
modprobe dummy
printf '# wormhole course mount exercise\n' >>/etc/fstab
if [[ $selinux_test == 1 ]]; then
  case $(getenforce) in
    Enforcing) selinux_mode=permissive; setenforce 0 ;;
    Permissive) selinux_mode=enforcing; setenforce 1 ;;
    *) printf 'SELinux is disabled in the provider image\n' >&2; exit 1 ;;
  esac
  sed -i "s/^SELINUX=.*/SELINUX=$selinux_mode/" /etc/selinux/config
fi

sqlite3 /var/lib/wormhole-fixture/lab.db <<'SQL'
create table events(id integer primary key, value text not null);
insert into events(value) values ('before-capture'), ('persistent-state'), ('third-row');
SQL

cat >/usr/local/bin/wormhole-fixture-writer <<'SCRIPT'
#!/bin/sh
while :; do
  date -u +%s%N >>/var/lib/wormhole-fixture/writer.log
  if mountpoint -q /srv/wormhole-volume; then
    date -u +%s%N >>/srv/wormhole-volume/lab/writer.log
  fi
  sleep 1
done
SCRIPT
chmod 0755 /usr/local/bin/wormhole-fixture-writer
cat >/etc/systemd/system/wormhole-fixture-writer.service <<'UNIT'
[Unit]
Description=Wormhole generic state writer fixture
[Service]
ExecStart=/usr/local/bin/wormhole-fixture-writer
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wormhole-fixture-tick.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'date -u +%%s >>/var/lib/wormhole-fixture/timer.log'
UNIT
cat >/etc/systemd/system/wormhole-fixture-tick.timer <<'UNIT'
[Timer]
OnBootSec=1s
OnUnitActiveSec=30s
Unit=wormhole-fixture-tick.service
[Install]
WantedBy=timers.target
UNIT
cat >/etc/systemd/system/wormhole-fixture-disabled.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
UNIT
install -d /mnt/wormhole-course
cat >'/etc/systemd/system/mnt-wormhole\x2dcourse.mount' <<'UNIT'
[Unit]
Description=Wormhole lab-created mount fixture
[Mount]
What=tmpfs
Where=/mnt/wormhole-course
Type=tmpfs
Options=size=4m
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wormhole-fixture-path.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'date -u +%%s >>/var/lib/wormhole-fixture/path.log'
UNIT
cat >/etc/systemd/system/wormhole-fixture-path.path <<'UNIT'
[Path]
PathChanged=/opt/wormhole-fixture/path-trigger
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wormhole-fixture-socket.service <<'UNIT'
[Service]
ExecStart=/bin/cat
StandardInput=socket
UNIT
cat >/etc/systemd/system/wormhole-fixture-socket.socket <<'UNIT'
[Socket]
ListenStream=127.0.0.1:18082
[Install]
WantedBy=sockets.target
UNIT
install -d /usr/local/lib/systemd/system
cat >/usr/local/lib/systemd/system/wormhole-fixture-masked.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
UNIT
for webroot in /var/www/html /usr/share/nginx/html /srv/www/htdocs; do
  if [[ -d $webroot ]]; then
    printf 'wormhole web state\n' >"$webroot/index.html"
  fi
done
systemctl daemon-reload
systemctl enable --now wormhole-firewall.service wormhole-fixture-writer.service wormhole-fixture-tick.timer wormhole-fixture-path.path wormhole-fixture-socket.socket nginx.service 'mnt-wormhole\x2dcourse.mount'
systemctl disable --now wormhole-fixture-disabled.service
systemctl mask wormhole-fixture-masked.service
printf 'trigger\n' >/opt/wormhole-fixture/path-trigger
sleep 3
test -s /var/lib/wormhole-fixture/path.log
curl --fail --silent http://127.0.0.1/ | grep -qx 'wormhole web state'
if [[ $container_test == 1 ]]; then
  curl --fail --silent http://127.0.0.1:18081/ | grep -qx 'container state survived'
fi
sync
REMOTE
}

mutate_robust_source() {
  remote 'bash -se' <<'REMOTE'
set -Eeuo pipefail
command -v apt-get >/dev/null || { printf 'robust fixture currently requires an apt image\n' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1
apt-get install -y -qq --no-install-recommends python3-venv python3-setuptools python3-wheel nodejs npm postgresql golang-go

install -d /opt/wormhole-python-src /opt/wormhole-python /var/lib/wormhole-python
cat >/opt/wormhole-python-src/setup.py <<'PY'
from setuptools import setup
setup(name="wormhole-probe", version="1.0.0", py_modules=["wormhole_probe"])
PY
cat >/opt/wormhole-python-src/wormhole_probe.py <<'PY'
from pathlib import Path
def value():
    return Path("/var/lib/wormhole-python/value").read_text().strip()
PY
python3 -m venv --system-site-packages /opt/wormhole-python/venv
/opt/wormhole-python/venv/bin/pip install --no-index --no-build-isolation /opt/wormhole-python-src
printf 'python-state-v1\n' >/var/lib/wormhole-python/value
cat >/opt/wormhole-python/app.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from wormhole_probe import value
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (value() + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass
HTTPServer(("127.0.0.1", 18083), Handler).serve_forever()
PY

install -d /opt/wormhole-node-dep /opt/wormhole-node /var/lib/wormhole-node
cat >/opt/wormhole-node-dep/package.json <<'JSON'
{"name":"wormhole-probe","version":"1.0.0","main":"index.js"}
JSON
cat >/opt/wormhole-node-dep/index.js <<'JS'
exports.value = path => require('fs').readFileSync(path, 'utf8').trim();
JS
cat >/opt/wormhole-node/package.json <<'JSON'
{"name":"wormhole-node-app","version":"1.0.0","private":true}
JSON
(cd /opt/wormhole-node && npm install --no-audit --no-fund /opt/wormhole-node-dep)
printf 'node-state-v1\n' >/var/lib/wormhole-node/value
cat >/opt/wormhole-node/app.js <<'JS'
const http = require('http');
const probe = require('wormhole-probe');
http.createServer((_, response) => response.end(probe.value('/var/lib/wormhole-node/value') + '\n')).listen(18084, '127.0.0.1');
JS

install -d /opt/wormhole-go /var/lib/wormhole-go
cat >/opt/wormhole-go/go.mod <<'GO'
module wormhole-go-probe
go 1.22
GO
cat >/opt/wormhole-go/main.go <<'GO'
package main
import (
  "fmt"
  "os"
  "strings"
)
func main() {
  value, err := os.ReadFile("/var/lib/wormhole-go/value")
  if err != nil { panic(err) }
  fmt.Println(strings.TrimSpace(string(value)))
}
GO
printf 'go-state-v1\n' >/var/lib/wormhole-go/value
(cd /opt/wormhole-go && go build -trimpath -o /usr/local/bin/wormhole-go-probe .)

systemctl enable --now postgresql.service
runuser -u postgres -- createdb wormhole_course
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d wormhole_course <<'SQL'
create table events(id bigserial primary key, value text not null);
insert into events(value) values ('seed-one'), ('seed-two'), ('seed-three');
SQL

cat >/etc/systemd/system/wormhole-python.service <<'UNIT'
[Unit]
After=network.target
[Service]
User=wormhole-lab
ExecStart=/opt/wormhole-python/venv/bin/python /opt/wormhole-python/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wormhole-node.service <<'UNIT'
[Unit]
After=network.target
[Service]
User=wormhole-lab
ExecStart=/usr/bin/node /opt/wormhole-node/app.js
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wormhole-postgres-writer.service <<'UNIT'
[Unit]
Requires=postgresql.service
After=postgresql.service
[Service]
User=postgres
ExecStart=/bin/sh -c 'while :; do /usr/bin/psql -d wormhole_course -c "insert into events(value) values (clock_timestamp()::text)" >/dev/null; sleep 1; done'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wormhole-python.service wormhole-node.service wormhole-postgres-writer.service
sleep 3
curl --fail --silent http://127.0.0.1:18083/ | grep -qx 'python-state-v1'
curl --fail --silent http://127.0.0.1:18084/ | grep -qx 'node-state-v1'
[[ $(wormhole-go-probe) == go-state-v1 ]]
(( $(runuser -u postgres -- psql -At -d wormhole_course -c 'select count(*) from events') > 3 ))
sync
REMOTE
}

record_source_oracle() {
  local container_test=$1 robust_test=$2 selinux_test=$3
  remote bash -se -- "$container_test" "$robust_test" "$selinux_test" <<'REMOTE'
set -Eeuo pipefail
container_test=$1 robust_test=$2 selinux_test=$3
printf 'db_rows=%s\n' "$(sqlite3 /var/lib/wormhole-fixture/lab.db 'select count(*) from events;')"
printf 'writer_rows=%s\n' "$(wc -l </var/lib/wormhole-fixture/writer.log)"
printf 'modified_sha256=%s\n' "$(sha256sum /opt/wormhole-fixture/modified.txt | cut -d ' ' -f1)"
printf 'modified_xattr=%s\n' "$(getfattr --only-values -n user.wormhole /opt/wormhole-fixture/modified.txt)"
printf 'lab_uid=%s\n' "$(id -u wormhole-lab)"
printf 'container_fixture=%s\n' "$([[ $container_test == 1 ]] && printf true || printf false)"
printf 'robust_fixture=%s\n' "$([[ $robust_test == 1 ]] && printf true || printf false)"
printf 'selinux_fixture=%s\n' "$([[ $selinux_test == 1 ]] && printf true || printf false)"
printf 'selinux_mode=%s\n' "$([[ $selinux_test == 1 ]] && getenforce || true)"
if mountpoint -q /srv/wormhole-volume; then
  printf 'volume_fixture=true\n'
  printf 'volume_filesystem=%s\n' "$(findmnt -n -o FSTYPE /srv/wormhole-volume)"
  printf 'volume_digest=%s\n' "$(find /srv/wormhole-volume/lab/corpus -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d ' ' -f1)"
  printf 'volume_writer_rows=%s\n' "$(wc -l </srv/wormhole-volume/lab/writer.log)"
  if [[ -f /srv/wormhole-volume/lab/continued.txt ]]; then
    printf 'volume_continued_sha256=%s\n' "$(sha256sum /srv/wormhole-volume/lab/continued.txt | cut -d ' ' -f1)"
  else
    printf 'volume_continued_sha256=absent\n'
  fi
else
  printf 'volume_fixture=false\nvolume_filesystem=\nvolume_digest=\nvolume_writer_rows=\nvolume_continued_sha256=absent\n'
fi
if [[ -f /opt/wormhole-fixture/continued-work.txt ]]; then
  printf 'continued_sha256=%s\n' "$(sha256sum /opt/wormhole-fixture/continued-work.txt | cut -d ' ' -f1)"
else
  printf 'continued_sha256=absent\n'
fi
if [[ $robust_test == 1 ]]; then
  systemctl start postgresql.service
  postgres_max=$(runuser -u postgres -- psql -At -d wormhole_course -c 'select max(id) from events')
  postgres_checksum=$(runuser -u postgres -- psql -At -d wormhole_course -c "select md5(coalesce(string_agg(id::text || ':' || value, ',' order by id), '')) from events where id <= $postgres_max")
  printf 'postgres_max=%s\n' "$postgres_max"
  printf 'postgres_checksum=%s\n' "$postgres_checksum"
  printf 'python_value=%s\n' "$(cat /var/lib/wormhole-python/value)"
  printf 'node_value=%s\n' "$(cat /var/lib/wormhole-node/value)"
  printf 'go_value=%s\n' "$(wormhole-go-probe)"
fi
REMOTE
}

validate_target() {
  local source_oracle=$1 expected_rows expected_hash expected_xattr container_fixture continued_sha256 robust_fixture
  local postgres_max postgres_checksum python_value node_value go_value volume_fixture volume_filesystem volume_digest volume_continued_sha256 selinux_fixture selinux_mode
  expected_rows=$(awk -F= '$1=="db_rows" {print $2}' "$source_oracle")
  expected_hash=$(awk -F= '$1=="modified_sha256" {print $2}' "$source_oracle")
  expected_xattr=$(awk -F= '$1=="modified_xattr" {print $2}' "$source_oracle")
  container_fixture=$(awk -F= '$1=="container_fixture" {print $2}' "$source_oracle")
  continued_sha256=$(awk -F= '$1=="continued_sha256" {print $2}' "$source_oracle")
  robust_fixture=$(awk -F= '$1=="robust_fixture" {print $2}' "$source_oracle")
  postgres_max=$(awk -F= '$1=="postgres_max" {print $2}' "$source_oracle")
  postgres_checksum=$(awk -F= '$1=="postgres_checksum" {print $2}' "$source_oracle")
  python_value=$(awk -F= '$1=="python_value" {print $2}' "$source_oracle")
  node_value=$(awk -F= '$1=="node_value" {print $2}' "$source_oracle")
  go_value=$(awk -F= '$1=="go_value" {print $2}' "$source_oracle")
  volume_fixture=$(awk -F= '$1=="volume_fixture" {print $2}' "$source_oracle")
  volume_filesystem=$(awk -F= '$1=="volume_filesystem" {print $2}' "$source_oracle")
  volume_digest=$(awk -F= '$1=="volume_digest" {print $2}' "$source_oracle")
  volume_continued_sha256=$(awk -F= '$1=="volume_continued_sha256" {print $2}' "$source_oracle")
  selinux_fixture=$(awk -F= '$1=="selinux_fixture" {print $2}' "$source_oracle")
  selinux_mode=$(awk -F= '$1=="selinux_mode" {print $2}' "$source_oracle")
  remote bash -se -- "$expected_rows" "$expected_hash" "$expected_xattr" "$container_fixture" "$continued_sha256" "$robust_fixture" "$postgres_max" "$postgres_checksum" "$python_value" "$node_value" "$go_value" "$volume_fixture" "$volume_filesystem" "$volume_digest" "$volume_continued_sha256" "$selinux_fixture" "$selinux_mode" <<'REMOTE'
set -Eeuo pipefail
trap 'printf "validation_failed_line=%s\n" "$LINENO" >&2' ERR
expected_rows=$1 expected_hash=$2 expected_xattr=$3 container_fixture=$4 continued_sha256=$5 robust_fixture=$6
postgres_max=${7:-} postgres_checksum=${8:-} python_value=${9:-} node_value=${10:-} go_value=${11:-}
volume_fixture=${12:-false} volume_filesystem=${13:-} volume_digest=${14:-} volume_continued_sha256=${15:-absent}
selinux_fixture=${16:-false}
selinux_mode=${17:-}
[[ ! -e /opt/wormhole-fixture/delete-me.txt ]]
[[ -L /opt/wormhole-fixture/type-change ]]
[[ $(readlink /opt/wormhole-fixture/type-change) == /etc/os-release ]]
[[ -f $'/opt/wormhole-fixture/name[1]\nsecond-line' ]]
[[ $(stat -c '%a' /opt/wormhole-fixture/modified.txt) == 640 ]]
[[ $(sha256sum /opt/wormhole-fixture/modified.txt | cut -d ' ' -f1) == "$expected_hash" ]]
[[ $(getfattr --only-values -n user.wormhole /opt/wormhole-fixture/modified.txt) == "$expected_xattr" ]]
[[ $(id -u wormhole-lab) == 23123 ]]
[[ $(cat /home/wormhole-lab/state.txt) == account-data ]]
grep -q 'wormhole-lab$' /home/wormhole-lab/.ssh/authorized_keys
[[ $(stat -c '%a:%u' /home/wormhole-lab/.ssh/authorized_keys) == 600:23123 ]]
[[ $(stat -c '%i' /opt/wormhole-fixture/hardlink-a) == $(stat -c '%i' /opt/wormhole-fixture/hardlink-b) ]]
[[ -p /opt/wormhole-fixture/course.fifo ]]
sparse_size=$(stat -c '%s' /opt/wormhole-fixture/sparse.img)
sparse_blocks=$(stat -c '%b' /opt/wormhole-fixture/sparse.img)
[[ $sparse_size == 67108864 ]] || { printf 'sparse_size=%s expected=67108864\n' "$sparse_size" >&2; false; }
(( sparse_blocks * 512 < 67108864 )) || { printf 'sparse_blocks=%s expected_bytes_below=67108864\n' "$sparse_blocks" >&2; false; }
getfacl -cp /opt/wormhole-fixture/modified.txt | grep -q '^user:wormhole-lab:r--$'
getcap /opt/wormhole-fixture/capability-binary | grep -q 'cap_net_bind_service=ep'
grep -qx 'vm.swappiness = 17' /etc/sysctl.d/99-wormhole-course.conf
[[ $(sysctl -n vm.swappiness) == 17 ]]
grep -q '^dummy ' /proc/modules
grep -qx 'dummy' /etc/modules-load.d/wormhole-course.conf
grep -qx '# wormhole course mount exercise' /etc/fstab
test -f /etc/cron.d/wormhole-course
[[ $(sqlite3 /var/lib/wormhole-fixture/lab.db 'select count(*) from events;') == "$expected_rows" ]]
command -v getfattr nginx sqlite3 >/dev/null
if command -v tree >/dev/null; then exit 1; fi
nft list table inet wormhole_course >/dev/null
systemctl is-active --quiet wormhole-firewall.service
grep -qx '192.0.2.123 wormhole-course.local' /etc/hosts
grep -q 'wormhole-course-key$' /root/.ssh/authorized_keys
while IFS= read -r target_host_line; do
  grep -Fqx -- "$target_host_line" /etc/hosts
done </var/lib/wormhole/target-hosts-before
systemctl is-active --quiet nginx.service
systemctl is-active --quiet wormhole-fixture-writer.service
systemctl is-active --quiet wormhole-fixture-tick.timer
systemctl is-active --quiet wormhole-fixture-path.path
systemctl is-active --quiet wormhole-fixture-socket.socket
systemctl is-active --quiet 'mnt-wormhole\x2dcourse.mount'
[[ $(findmnt -n -o FSTYPE /mnt/wormhole-course) == tmpfs ]]
if systemctl is-active --quiet wormhole-fixture-disabled.service; then exit 1; fi
masked_state=$(systemctl is-enabled wormhole-fixture-masked.service || true)
[[ $masked_state == masked ]]
curl --fail --silent http://127.0.0.1/ | grep -qx 'wormhole web state'
if [[ $container_fixture == true ]]; then
  systemctl is-active --quiet docker.service
  [[ $(docker inspect -f '{{.State.Running}}' wormhole-course) == true ]]
  [[ $(docker exec wormhole-course /busybox cat /data/value) == volume-state ]]
  [[ $(docker exec wormhole-course /busybox cat /layer-state) == writable-layer ]]
  curl --fail --silent http://127.0.0.1:18081/ | grep -qx 'container state survived'
  docker exec wormhole-course /busybox sh -c 'printf after-restore >/data/continued'
  [[ $(docker exec wormhole-course /busybox cat /data/continued) == after-restore ]]
fi
if [[ $continued_sha256 == absent ]]; then
  [[ ! -e /opt/wormhole-fixture/continued-work.txt ]]
else
  [[ $(sha256sum /opt/wormhole-fixture/continued-work.txt | cut -d ' ' -f1) == "$continued_sha256" ]]
fi
if [[ $robust_fixture == true ]]; then
  command -v node npm go psql wormhole-go-probe >/dev/null
  /opt/wormhole-python/venv/bin/python -c 'import wormhole_probe'
  (cd /opt/wormhole-node && npm ls --silent wormhole-probe >/dev/null)
  systemctl is-active --quiet wormhole-python.service wormhole-node.service postgresql.service wormhole-postgres-writer.service
  [[ $(curl --fail --silent http://127.0.0.1:18083/) == "$python_value" ]]
  [[ $(curl --fail --silent http://127.0.0.1:18084/) == "$node_value" ]]
  [[ $(wormhole-go-probe) == "$go_value" ]]
  current_postgres_max=$(runuser -u postgres -- psql -At -d wormhole_course -c 'select max(id) from events')
  (( current_postgres_max >= postgres_max ))
  current_postgres_checksum=$(runuser -u postgres -- psql -At -d wormhole_course -c "select md5(coalesce(string_agg(id::text || ':' || value, ',' order by id), '')) from events where id <= $postgres_max")
  [[ $current_postgres_checksum == "$postgres_checksum" ]]
fi
if [[ $volume_fixture == true ]]; then
  mountpoint -q /srv/wormhole-volume
  [[ $(findmnt -n -o FSTYPE /srv/wormhole-volume) == "$volume_filesystem" ]]
  [[ $(find /srv/wormhole-volume/lab/corpus -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d ' ' -f1) == "$volume_digest" ]]
  volume_before=$(wc -l </srv/wormhole-volume/lab/writer.log)
  sleep 2
  (( $(wc -l </srv/wormhole-volume/lab/writer.log) > volume_before ))
  if [[ $volume_continued_sha256 == absent ]]; then
    [[ ! -e /srv/wormhole-volume/lab/continued.txt ]]
  else
    [[ $(sha256sum /srv/wormhole-volume/lab/continued.txt | cut -d ' ' -f1) == "$volume_continued_sha256" ]]
  fi
fi
if [[ $selinux_fixture == true ]]; then
  [[ $(getenforce) == "$selinux_mode" ]]
  grep -qix "SELINUX=$selinux_mode" /etc/selinux/config
fi
before=$(wc -l </var/lib/wormhole-fixture/writer.log)
path_before=$(wc -l </var/lib/wormhole-fixture/path.log)
printf 'after-restore\n' >>/opt/wormhole-fixture/path-trigger
sleep 2
after=$(wc -l </var/lib/wormhole-fixture/writer.log)
(( after > before ))
(( $(wc -l </var/lib/wormhole-fixture/path.log) > path_before ))
sqlite3 /var/lib/wormhole-fixture/lab.db "insert into events(value) values ('after-restore');"
[[ $(sqlite3 /var/lib/wormhole-fixture/lab.db 'select count(*) from events;') == $((expected_rows + 1)) ]]
printf 'continued-work\n' >/opt/wormhole-fixture/continued-work.txt
if [[ $volume_fixture == true ]]; then
  printf 'continued-volume-work\n' >/srv/wormhole-volume/lab/continued.txt
fi
if [[ $robust_fixture == true ]]; then
  printf 'python-state-v2\n' >/var/lib/wormhole-python/value
  printf 'node-state-v2\n' >/var/lib/wormhole-node/value
  printf 'go-state-v2\n' >/var/lib/wormhole-go/value
  runuser -u postgres -- psql -d wormhole_course -c "insert into events(value) values ('after-restore')" >/dev/null
fi
printf 'validated=true\nwriter_before=%s\nwriter_after=%s\n' "$before" "$after"
REMOTE
}

log "building Wormhole binaries"
(cd "$root" && make build >/dev/null)
wormhole_sha256=$(sha256sum "$root/bin/wormhole" | cut -d ' ' -f1)
restic_sha256=$(sha256sum "$root/bin/restic" | cut -d ' ' -f1)
log "validating S3 bucket access"
curl --silent --show-error --fail \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  --aws-sigv4 "aws:amz:$AWS_DEFAULT_REGION:s3" \
  "https://${S3_ENDPOINT}/${S3_BUCKET}?list-type=2&max-keys=1" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C "wormhole-e2e-$run_id" -f "$key"
key_body=$(jq -n --arg name "wormhole-e2e-$run_id" --arg public_key "$(cat "$key.pub")" '{name:$name,public_key:$public_key}')
key_response=$(api POST /ssh_keys "$key_body")
ssh_key_id=$(jq -er '.ssh_key.id' <<<"$key_response")
log "created temporary SSH key $ssh_key_id"

read -r -a images <<<"$TEST_IMAGES"
for image in "${images[@]}"; do
  environment="e2e-${run_id}-${image//[^a-zA-Z0-9]/-}"
  repository="s3:https://${S3_ENDPOINT}/${S3_BUCKET}/${WORMHOLE_S3_PREFIX}/${run_id}/${image}"
  corruption_test=0
  [[ -n $CORRUPTION_TEST_IMAGE && $image == "$CORRUPTION_TEST_IMAGE" ]] && corruption_test=1
  lock_test=0
  [[ -n $LOCK_TEST_IMAGE && $image == "$LOCK_TEST_IMAGE" ]] && lock_test=1

  create_server "$image" source
  install_wormhole
  write_remote_env "$environment" "$repository"
  seed_base
  log "$image: recording baseline"
  remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-baseline.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole baseline create'" | tee "$report_dir/$image-baseline.json"
  if (( corruption_test == 1 )); then
    remote 'set -a; . /run/wormhole.env; set +a; restic list packs' | sort >"$report_dir/$image-baseline-packs.txt"
  fi
  container_test=0
  [[ $image == "$CONTAINER_TEST_IMAGE" ]] && container_test=1
  robust_test=0
  [[ -n $ROBUST_TEST_IMAGE && $image == "$ROBUST_TEST_IMAGE" ]] && robust_test=1
  selinux_test=0
  [[ -n $SELINUX_TEST_IMAGE && $image == "$SELINUX_TEST_IMAGE" ]] && selinux_test=1
  interruption_test=0
  [[ -n $INTERRUPTION_TEST_IMAGE && $image == "$INTERRUPTION_TEST_IMAGE" ]] && interruption_test=1
  mutate_source "$container_test" "$selinux_test"
  (( robust_test == 0 )) || mutate_robust_source
  if (( interruption_test == 1 )); then
    log "$image: crashing once during capture backup"
    install_crash_wrapper backup
    before_boot=$(remote 'cat /proc/sys/kernel/random/boot_id')
    if remote_bounded "systemd-run --quiet --wait --pipe --collect --unit=wormhole-capture.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole capture run --leave-stopped'" >"$report_dir/$image-interrupted-capture.txt" 2>&1; then
      die "$image interrupted capture unexpectedly succeeded"
    fi
    wait_for_boot_change "$before_boot"
    remove_crash_wrapper
    mount_current_volume
    write_remote_env "$environment" "$repository"
    if remote 'set -a; . /run/wormhole.env; set +a; wormhole inspect' >"$report_dir/$image-interrupted-capture-inspect.txt" 2>&1; then
      die "$image interrupted capture committed a manifest"
    fi
  fi
  log "$image: capturing changed lab"
  remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-capture.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole capture run --leave-stopped'" | tee "$report_dir/$image-capture.json"
  record_source_oracle "$container_test" "$robust_test" "$selinux_test" | tee "$report_dir/$image-source-oracle.txt"
  remote 'set -a; . /run/wormhole.env; set +a; wormhole inspect' >"$report_dir/$image-manifest.json"
  captured_kernel=$(jq -er '.captured_system.kernel' "$report_dir/$image-manifest.json")
  if (( corruption_test == 1 )); then
    remote 'set -a; . /run/wormhole.env; set +a; restic list packs' | sort >"$report_dir/$image-capture-packs.txt"
  fi
  source_id=$current_server
  delete_server "$source_id"

  create_compatible_target "$image" target "$captured_kernel"
  log "$image: proving source-fence rejection"
  if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply'" >"$report_dir/$image-source-fence-rejection.txt" 2>&1; then
    die "$image restore succeeded without --source-fenced"
  fi
  if [[ -n $current_volume ]]; then
    log "$image: proving attached-volume preflight failures"
    remote 'umount /srv/wormhole-volume'
    if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-missing-volume-rejection.txt" 2>&1; then
      die "$image restore accepted a missing required volume"
    fi
    grep -q 'required_mount_missing' "$report_dir/$image-missing-volume-rejection.txt" || die "$image missing-volume rejection returned the wrong failure"
    remote 'mount -t tmpfs -o size=128m tmpfs /srv/wormhole-volume'
    if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-wrong-volume-filesystem-rejection.txt" 2>&1; then
      die "$image restore accepted the wrong volume filesystem"
    fi
    grep -q 'mount_filesystem_mismatch' "$report_dir/$image-wrong-volume-filesystem-rejection.txt" || die "$image wrong-filesystem rejection returned the wrong failure"
    remote 'umount /srv/wormhole-volume'
    mount_current_volume
    # shellcheck disable=SC2016
    remote 'available=$(df -B1 --output=avail /srv/wormhole-volume | tail -n1); (( available > 100663296 )); fallocate -l $((available - 33554432)) /srv/wormhole-volume/.wormhole-space-test'
    if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-insufficient-space-rejection.txt" 2>&1; then
      die "$image restore accepted insufficient volume space"
    fi
    grep -q 'insufficient_space' "$report_dir/$image-insufficient-space-rejection.txt" || die "$image insufficient-space rejection returned the wrong failure"
    remote 'rm -f /srv/wormhole-volume/.wormhole-space-test'
  fi
  remote 'printf target-drift >/opt/wormhole-fixture/target-drift.txt'
  log "$image: proving target-drift rejection"
  if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-target-drift-rejection.txt" 2>&1; then
    die "$image restore accepted a target that differed from its baseline"
  fi
  grep -q 'target_baseline_mismatch' "$report_dir/$image-target-drift-rejection.txt" || die "$image drift rejection returned the wrong failure"
  remote 'rm /opt/wormhole-fixture/target-drift.txt'
  log "$image: proving bad repository password fails closed"
  if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; RESTIC_PASSWORD=wrong-password; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-bad-password-rejection.txt" 2>&1; then
    die "$image restore accepted a bad repository password"
  fi
  if (( lock_test == 1 )); then
    log "$image: proving a live repository lease blocks restore"
    remote "systemd-run --quiet --unit=wormhole-held-lock.service /bin/bash -c 'set -a; . /run/wormhole.env; HOME=/root; export HOME; set +a; tail -f /dev/null | restic wormhole-lock'"
    sleep 2
    remote 'systemctl is-active --quiet wormhole-held-lock.service'
    if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-live-lock-rejection.txt" 2>&1; then
      die "$image restore ignored a live repository lease"
    fi
    remote 'systemctl kill --kill-whom=all --signal=KILL wormhole-held-lock.service 2>/dev/null || true; while systemctl is-active --quiet wormhole-held-lock.service; do sleep 1; done'
  fi
  if (( corruption_test == 1 )); then
    log "$image: proving repository corruption fails closed"
    corrupt_capture_pack "$image"
    if remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-corrupt-pack-rejection.txt" 2>&1; then
      die "$image restore accepted a corrupted repository pack"
    fi
    remote 'wormhole status' >"$report_dir/$image-corrupt-pack-status.json"
    jq -e 'map(select(.kind == "restore")) | all(.status != "complete")' "$report_dir/$image-corrupt-pack-status.json" >/dev/null \
      || die "$image corrupted restore reported complete"
    repair_corruption
  fi
  if (( interruption_test == 1 )); then
    log "$image: crashing once during restore apply"
    install_crash_wrapper restore
    before_boot=$(remote 'cat /proc/sys/kernel/random/boot_id')
    if remote_bounded "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" >"$report_dir/$image-interrupted-restore.txt" 2>&1; then
      die "$image interrupted restore unexpectedly succeeded"
    fi
    wait_for_boot_change "$before_boot"
    remove_crash_wrapper
    mount_current_volume
    write_remote_env "$environment" "$repository"
    remote 'wormhole status' | tee "$report_dir/$image-interrupted-restore-status.json" >/dev/null
    jq -e 'map(select(.kind == "restore")) | any(.phase == "apply" and .status != "complete")' "$report_dir/$image-interrupted-restore-status.json" >/dev/null \
      || die "$image interrupted restore did not retain its apply checkpoint"
  fi
  log "$image: restoring onto fresh target"
  remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced'" | tee "$report_dir/$image-restore.json"
  if (( REBOOT_AFTER_RESTORE == 1 )); then
    log "$image: rebooting restored target"
    reboot_and_wait
    mount_current_volume
    write_remote_env "$environment" "$repository"
  fi
  validate_target "$report_dir/$image-source-oracle.txt" | tee "$report_dir/$image-validation.txt"
  if [[ -n $current_volume ]]; then
    remote 'test -f /srv/wormhole-volume/lab/continued.txt' || die "$image continued volume write disappeared before recapture"
  fi
  remote 'test -s /var/lib/wormhole/baseline.json'
  log "$image: recapturing continued work from the restored VM"
  remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-capture.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole capture run --leave-stopped'" | tee "$report_dir/$image-recapture.json"
  if [[ -n $current_volume ]]; then
    remote 'test -f /srv/wormhole-volume/lab/continued.txt' || die "$image continued volume write disappeared during recapture"
  fi
  second_manifest=$(jq -er '.manifest_snapshot_id' "$report_dir/$image-recapture.json")
  record_source_oracle "$container_test" "$robust_test" "$selinux_test" | tee "$report_dir/$image-second-source-oracle.txt"
  remote "set -a; . /run/wormhole.env; set +a; wormhole inspect --manifest '$second_manifest'" >"$report_dir/$image-second-manifest.json"
  remote 'wormhole status' >"$report_dir/$image-jobs.json"
  target_id=$current_server
  delete_server "$target_id"

  create_compatible_target "$image" successor "$captured_kernel"
  log "$image: restoring continued-work capture onto third VM"
  remote "systemd-run --quiet --wait --pipe --collect --unit=wormhole-restore.service /bin/bash -c 'set -a; . /run/wormhole.env; set +a; exec wormhole restore apply --source-fenced --manifest $second_manifest'" | tee "$report_dir/$image-second-restore.json"
  if (( REBOOT_AFTER_RESTORE == 1 )); then
    log "$image: rebooting restored successor"
    reboot_and_wait
    mount_current_volume
    write_remote_env "$environment" "$repository"
  fi
  validate_target "$report_dir/$image-second-source-oracle.txt" | tee "$report_dir/$image-second-validation.txt"
  remote 'wormhole status' >"$report_dir/$image-second-jobs.json"
  successor_id=$current_server
  delete_server "$successor_id"
  log "$image: lifecycle passed"
done

jq -n \
  --arg run_id "$run_id" --arg wormhole_sha256 "$wormhole_sha256" --arg restic_sha256 "$restic_sha256" \
  --argjson images "$(printf '%s\n' "${images[@]}" | jq -Rsc 'split("\n")[:-1]')" \
  '{status:"passed",run_id:$run_id,images:$images,binaries:{wormhole_sha256:$wormhole_sha256,restic_sha256:$restic_sha256}}' \
  | tee "$report_dir/result.json"
