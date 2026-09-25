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

func withMissingCapabilities(t *testing.T, missing ...string) {
	previous := missingCapabilities
	t.Cleanup(func() { missingCapabilities = previous })
	missingCapabilities = func(required ...string) []string {
		var out []string
		for _, r := range required {
			if slices.Contains(missing, r) {
				out = append(out, r)
			}
		}
		return out
	}
}

func TestRequireCapabilities_NamesTheMissingOnes(t *testing.T) {
	withMissingCapabilities(t, "SYS_TIME", "SYS_BOOT")

	err := requireCapabilities("Time travel attacks", timeTravelCapabilities)

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
	assert.ErrorContains(t, err, "NET_ADMIN, SYS_TIME")
}
