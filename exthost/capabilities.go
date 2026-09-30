// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"fmt"
	"slices"
	"strings"

	extension_kit "github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extruntime"
)

// The capabilities the actions need in the extension's bounding set. The extension binary carries
// them as file capabilities without the effective bit, so it starts even when the container is not
// granted all of them; the actions needing a missing one fail in prepare instead of at run time.
var (
	// sidecarCapabilities are needed by every action that runs a sidecar container on the host:
	// runc/crun runs as root, enters the host's namespaces and cgroups, and brings up the loopback
	// interface of the sidecar's network namespace (NET_ADMIN).
	sidecarCapabilities = []string{"SETUID", "SETGID", "SYS_ADMIN", "SYS_CHROOT", "SYS_PTRACE", "DAC_OVERRIDE", "NET_ADMIN"}
	// networkCapabilities are needed by the network faults (tc, iptables, ip).
	networkCapabilities = slices.Concat(sidecarCapabilities, []string{"NET_RAW"})
	// dnsInjectionCapabilities are needed by the DNS error injection (an eBPF program).
	dnsInjectionCapabilities = slices.Concat(sidecarCapabilities, []string{"BPF"})
	// clockCapabilities shift the clock, from the extension's own process. Blocking NTP meanwhile
	// (disableNtp) also needs networkCapabilities.
	clockCapabilities = []string{"SYS_TIME"}
	// shutdownCapabilities reboot or power off the host, from the extension's own process.
	shutdownCapabilities = []string{"SYS_BOOT"}
	// stopProcessCapabilities kill processes of other users, through a root helper.
	stopProcessCapabilities = []string{"KILL", "SETUID", "SETGID"}
	// cpuSpeedCapabilities write the root-owned cpufreq files, from the extension's own process.
	cpuSpeedCapabilities = []string{"DAC_OVERRIDE"}

	// ExpectedCapabilities are all the capabilities the actions use; the missing ones are logged at
	// startup. SYS_RESOURCE is optional: without it, the sidecars are not protected from the OOM killer.
	ExpectedCapabilities = slices.Concat(networkCapabilities, []string{"BPF", "SYS_TIME", "SYS_BOOT", "KILL", "SYS_RESOURCE"})
)

// missingCapabilities and missingHeldCapabilities are replaced in tests.
var (
	missingCapabilities     = extruntime.MissingCapabilities
	missingHeldCapabilities = extruntime.MissingHeldCapabilities
)

// requireCapabilities fails the preparation of an action when the extension lacks a capability it
// needs, naming the missing ones.
func requireCapabilities(what string, required []string) error {
	return capabilitiesError(what, missingCapabilities(required...))
}

// requireHeldCapabilities is requireCapabilities for what the extension does in its own process (a
// syscall, writing a file), where the root helpers cannot help: the extension must hold them.
func requireHeldCapabilities(what string, required []string) error {
	return capabilitiesError(what, missingHeldCapabilities(required...))
}

func capabilitiesError(what string, missing []string) error {
	if len(missing) == 0 {
		return nil
	}
	return extension_kit.ToError(fmt.Sprintf("%s need the capabilities %s, which the extension does not have. "+
		"Add them to the capabilities of the extension's container securityContext.", what, strings.Join(missing, ", ")), nil)
}
