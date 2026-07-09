# Changelog

## Unreleased

- feat: new `Exclude IPs/CIDRs` parameter (`excludeIp`) on all network attacks sharing the hostname/IP/port filters (delay, loss, corruption, bandwidth, blackhole, TCP reset) — affect all traffic except the given IPs/CIDRs. Excludes always take precedence over the include restrictions. The existing filter parameters are relabeled to `Include Hostnames`, `Include IPs/CIDRs` and `Include Ports` to make the distinction explicit.

## v1.5.10

- feat: opt-in qdisc snapshot/restore for network attacks. Set `STEADYBIT_EXTENSION_NETWORK_STRICT_ROOT_QDISC=false` to make Apply capture the root qdisc tree (qdiscs + filters) of every target interface and Revert replay it after the attack's `tc del`. Preserves cloud-tuned root qdiscs (e.g. GKE's `mq + fq` with `buckets=32768 horizon=2s`) that would otherwise revert to kernel defaults after `tc qdisc del root` and leave the host network degraded until reboot. Off by default; Linux only.
- The pre-attack qdisc snapshot lives in the action's per-execution state instead of an in-memory map in the extension process. An extension pod restart between Start and Stop no longer loses the snapshot, so Stop still restores the cloud-tuned root tree.
- Update dependencies

## v1.5.9

- chore(deps): runc 1.4.3 and dns-inject to v0.2.2
- feat: set oom_score_adj directly via extension-kit (drop root subprocess) (#216)
- fix: switch back to use strict root qdisc checks

## v1.5.8

- feat: opt-in qdisc snapshot/restore for network attacks. Set `STEADYBIT_EXTENSION_NETWORK_SNAPSHOT_RESTORE=true` (e.g. via `extraEnv`) to make Apply capture the root qdisc tree (qdiscs + filters) of the target interface and Revert replay it after the attack's `tc del`. Preserves cloud-tuned root qdiscs (e.g. GKE's `mq + fq` with `buckets=32768 horizon=2s`) that would otherwise revert to kernel defaults after `tc qdisc del root` and leave the host network degraded until reboot. Off by default; Linux only.
- Network attacks (delay, loss, corruption, bandwidth) now work on hosts where the kernel has already attached a default root qdisc to the target interface (e.g. `mq` on GKE COS / EKS / AKS / RHCOS). Previously the attack failed to start with `NLM_F_REPLACE needed to override`. The kernel default (`mq`, `noqueue`, `fq_codel`, `pfifo_fast`, `fq`) is restored automatically after the attack ends.
- If the target interface carries a user- or CNI-installed root qdisc (e.g. `htb`, `cake`) that cannot be restored afterwards, the attack now fails fast in the prepare step with a clear error instead of silently replacing it.
- Optional fallback: set `STEADYBIT_EXTENSION_NETWORK_STRICT_ROOT_QDISC=true` (e.g. via `extraEnv`) to make network attacks refuse any interface whose root qdisc is not `noqueue` — including the kernel default `mq` — instead of replacing it. Off by default.
- New `privileged` chart value (default `false`): runs the extension in privileged mode and switches the managed `SecurityContextConstraint` to allow it. Needed on hardened nodes (e.g. CIS/STIG) where the container root filesystem is mounted `nosuid`, which voids the binary's file capabilities and breaks fault injection (`nsenter: operation not permitted`).
- Stress CPU with "All cores" now uses every online CPU on hosts with more than 32 cores (previously capped at 32 due to a `Cpus_allowed` mask parsing bug).

## v1.5.7

- chore: update dns-inject v0.2.1
- chore: update to go 1.26.4
- feat: add weekly auto patch-release workflow


## v1.5.6

- DNS Error Injection: new `hostname` parameter to restrict injection to DNS queries with matching query names (exact, case-insensitive, IDN-aware); also exposes the new `hostname_filtered` metric in the live statistics widget
- DNS Error Injection: clarify labels and descriptions for the `port` and `cidr` parameters — they apply to the DNS server, not to the queried domain
- Bump bundled `dns-inject` to v0.2.0

## v1.5.5

- Support discovery group attribute via `STEADYBIT_EXTENSION_DISCOVERY_GROUP` env var (or `discovery.group` Helm value) — when set, the extension adds `steadybit.group=<value>` to every discovered target
- Update dependencies

## v1.5.4

- Bump bundled `nsmount` to v1.1.1 — lowers the GLIBC requirement from 2.30 to 2.28, restoring `.deb`/`.rpm` installation on RHEL 8 / Debian 10
- Bump bundled `memfill` to v1.3.1

## v1.5.3

- Fix Linux package: binary paths for `nsmount`, `memfill` and `dns-inject` were unset or pointed at the wrong directory, causing memfill and DNS error injection attacks to fail on `.deb`/`.rpm` installations
- Update dependencies

## v1.5.2

- Bump dns-inject to v0.1.4

## v1.5.1

- Bump Go to 1.26.3
- Update dependencies

## v1.5.0

- Bump Go to 1.26.2
- add tcp reset attack
- add dns error inject attack

## v1.4.11

- Support if-none-match for the extension list endpoint
- feat(chart): split image.name into image.registry + image.name
- Support global.priorityClassName
- Update dependencies

## v1.4.10

- Fill Disk: validate permissions of the target directory

## v1.4.9

- Update dependencies

## v1.4.8

- Update dependencies

## v1.4.7

- Update dependencies

## v1.4.6

- Update dependencies

## v1.4.5

- Update dependencies

## v1.4.4

- feat: Network Delay - add option "TCP Data Packets Only" (PSH heuristic). Uses iptables marks + tc fwmark to delay only TCP data packets; UDP is not delayed. Honors ports/hosts/CIDRs via iptables filtering.
- Update dependencies

## v1.4.3

- Add new CPU Frequency attack
- Update dependencies

## v1.4.2

 - Update dependencies

## v1.4.1

 - Add STEADYBIT_EXTENSTION_DIG_TIMEOUT
 - Treat dns answers case insensitive

## v1.4.0

 - run steadybit sidecar containers using crun
 - use stressng --iomix (instead of --io) to stress io

## v1.3.2

- If stress/diskfill/memfill exits unexpetedly report this as error and not as failure

## v1.3.1

- fix: ignore cgroups for memfill

## v1.3.0

- feat: add option to disable runc for running attacks

## v1.2.37

- fix: propagate environment to started runc processes

## v1.2.36

- fix: experiment execution when using the host.hostname of the k8s downward API

## v1.2.35

- possibility to set the host.hostname attribute in the discovery by the k8s downward api


## v1.2.34

- rename "Host" to "Linux Host" in discovery

## v1.2.33

- safe defaults for stress-attacks
- update depdendencies

## v1.2.32

- fix shutdown/reboot always failing on plain EC2 instances
- Rename "Shutdown Host" to "Trigger Shutdown Host"

## v1.2.31

- remove dependency to lsns
- update dependencies
- require iproute-tc and libcap instead of /usr/sbin/tc and /usr/sbin/capsh

## v1.2.30

- Updated dependencies
- fix: fill disk/stress io fails when file permissions disallow write

## v1.2.29

- fix: stress cpu attack uses all configured CPUs and not all available CPUs

## v1.2.28

- chore: update dependecies (CVE-2024-11187 & CVE-2024-12705)

## v1.2.27

- Rename some network actions to explicitly contain the term "outgoing"
- Use runc binary from the opencontainers/runc project

## v1.2.26

- fix: improve container id to be unique by adding the execution id

## v1.2.25

- Use uid instead of name for user statement in Dockerfile

## v1.2.24

- chore: update dependencies
- fix: network actions if runc debug is enabled

## v1.2.23

- chore: update dependencies

## v1.2.22

- fix: fail block traffic early on hosts with cilium
- fix: only create network excludes which are necessary for the given includes
- fix: aggregate excludes to ip ranges if there are too many
- fix: fail early when too many tc rules are generated for a network attack

## v1.2.21

- feat: change default value for "jitter" in "Network Delay" attack to false
- feat: add memfill attack

## v1.2.20

- fixed ip rule v6 support check
- chore: update dependencies

## v1.2.19

- chore: update dependencies

## v1.2.17

- fix: Don't use the priomap defaults for network attacks, this might lead to unexpected behavior when TOS is set in packets

## v1.2.16

- feat: remove the restriction on cgroup2 mounts using nsdelegate

## v1.2.15

- added fallback attributes for availability zone of AWS to show one of AWS, GCP or Azure

## v1.2.14

- fail actions early when cgroup2 nsdelegation is causing problems
- support cidrs filters for the network attacks

## v1.2.13

- Update dependencies (go 1.22)
- Added noop mode for diskfill attack to avoid errors when the disk is already full enough
- Better logging to host shutdown / reboot

## v1.2.12

- Update dependencies

## v1.2.11

- Update dependencies

## v1.2.10

- Added hint if kernel modules are missing for tc

## v1.2.9

- Update dependencies

## v1.2.8

- Automatically set the `GOMEMLIMIT` (90% of cgroup limit) and `GOMAXPROCS`
- Disallow running multiple tc configurations at the same time

## v1.2.7

- Update dependencies

## v1.2.6

- Update dependencies

## v1.2.5

- Update dependencies

## v1.2.4

- Update dependencies

## v1.2.3

- Update dependencies

## v1.2.2

- Update dependencies

## v1.2.1

- Fix: don't apply ipv6 rules if kernel module was disabled

## v1.2.0

> Update to the latest helm chart steadybit-extension-host-1.0.33 needed!

- add flush, read_write, read_write_and_flush mode to stress io
- fill disk attack
- fix stress memory and stress cpu constrained by the cgroup of the extension container

## v1.1.12

- Added `pprof` endpoints for debugging purposes
- Update dependencies

## v1.1.11

- Possibility to exclude attributes from discovery

## v1.1.10

- Only generate exclude ip/tc rules for network interfaces that are up

## v1.1.9

- avoid duplicate tc/ip rules

## v1.1.8

- update dependencies

## v1.1.6

- migration to new unified steadybit actionIds and targetTypes

## v1.1.5

- update dependencies

## v1.1.4

- update dependencies

## v1.1.3

 - fix: stop process attack sometimes didn't stop

## v1.1.2

 - discovery: put the ipv6 addresses in `host.ipv6` and not `host.ipv4`

## v1.1.1

 - turn the rpm dependency for kernel-extra-modules into a recommendation

## v1.1.0

 - prefix host labels with `host.`

## v1.0.2

 - add support for unix domain sockets
 - build linux packages

## v1.0.1

 - Bugfixes

## v1.0.0

 - Initial release
