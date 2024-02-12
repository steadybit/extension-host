# Changelog

## 1.2.5

- Update dependencies

## 1.2.4

- Update dependencies

## 1.2.3

- Update dependencies

## 1.2.2

- Update dependencies

## 1.2.1

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
