# Changelog

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
