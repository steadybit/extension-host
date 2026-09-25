// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"slices"
	"testing"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	extension_kit "github.com/steadybit/extension-kit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMissingCapabilities stubs both checks: missing are unusable at all, notHeld only unusable
// by the extension's own process.
func withMissingCapabilities(t *testing.T, missing ...string) {
	withMissingAndNotHeldCapabilities(t, missing, nil)
}

func withMissingAndNotHeldCapabilities(t *testing.T, missing, notHeld []string) {
	previous, previousHeld := missingCapabilities, missingHeldCapabilities
	t.Cleanup(func() { missingCapabilities, missingHeldCapabilities = previous, previousHeld })
	filter := func(unusable []string) func(...string) []string {
		return func(required ...string) []string {
			var out []string
			for _, r := range required {
				if slices.Contains(unusable, r) {
					out = append(out, r)
				}
			}
			return out
		}
	}
	missingCapabilities = filter(missing)
	missingHeldCapabilities = filter(slices.Concat(missing, notHeld))
}

func TestRequireCapabilities_NamesTheMissingOnes(t *testing.T) {
	withMissingCapabilities(t, "SYS_TIME", "SYS_BOOT")

	err := requireHeldCapabilities("Time travel attacks", clockCapabilities)

	var extErr extension_kit.ExtensionError
	require.ErrorAs(t, err, &extErr)
	assert.Equal(t, "Time travel attacks need the capabilities SYS_TIME, which the extension does not have. "+
		"Add them to the capabilities of the extension's container securityContext.", extErr.Title)
	assert.NoError(t, requireCapabilities("Stress attacks", sidecarCapabilities), "stress does not need SYS_TIME")
	assert.ErrorContains(t, requireCapabilities("Shutdown attacks", shutdownCapabilities), "SYS_BOOT")
}

func TestRequireCapabilities_EverySidecarNeedsNetAdmin(t *testing.T) {
	withMissingCapabilities(t, "NET_ADMIN")

	// The sidecar brings up the loopback interface of its network namespace.
	assert.ErrorContains(t, requireCapabilities("Stress attacks", sidecarCapabilities), "NET_ADMIN")
}

func TestPrepare_FailsFastWithoutTheNeededCapability(t *testing.T) {
	withMissingCapabilities(t, "NET_ADMIN", "SYS_TIME")

	_, err := (&networkAction{}).Prepare(context.Background(), &NetworkActionState{}, action_kit_api.PrepareActionRequestBody{})
	assert.ErrorContains(t, err, "NET_ADMIN")

	_, err = (&timeTravelAction{}).Prepare(context.Background(), &TimeTravelActionState{}, action_kit_api.PrepareActionRequestBody{})
	assert.ErrorContains(t, err, "SYS_TIME")
}

func TestTimeTravelPrepare_NeedsTheNetworkOnlyToBlockNTP(t *testing.T) {
	withMissingCapabilities(t, "NET_RAW")
	withoutNtp := action_kit_api.PrepareActionRequestBody{Config: map[string]any{"disableNtp": false, "offset": 5000},
		Target: &action_kit_api.Target{Attributes: map[string][]string{"host.hostname": {"host-1"}}}}
	blockingNtp := action_kit_api.PrepareActionRequestBody{Config: map[string]any{"disableNtp": true, "offset": 5000}}

	_, err := (&timeTravelAction{}).Prepare(context.Background(), &TimeTravelActionState{}, withoutNtp)
	assert.NotContains(t, errString(err), "capabilities", "shifting the clock needs SYS_TIME only")

	_, err = (&timeTravelAction{}).Prepare(context.Background(), &TimeTravelActionState{}, blockingNtp)
	assert.ErrorContains(t, err, "Time travel attacks blocking NTP need the capabilities NET_RAW")
}

func TestShutdownPrepare_NeedsSysBootHeldByTheExtension(t *testing.T) {
	// A root helper could get SYS_BOOT, but the reboot syscall runs in the extension's process.
	withMissingAndNotHeldCapabilities(t, nil, []string{"SYS_BOOT"})

	_, err := (&shutdownAction{}).Prepare(context.Background(), &ActionState{}, action_kit_api.PrepareActionRequestBody{})

	assert.ErrorContains(t, err, "Shutdown attacks need the capabilities SYS_BOOT")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
