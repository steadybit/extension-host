// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"testing"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/steadybit/extension-host/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapToExecutionContextWithoutExecutionContext(t *testing.T) {
	assert.NotPanics(t, func() {
		eCtx := mapToExecutionContext(action_kit_api.PrepareActionRequestBody{})
		assert.Empty(t, eCtx.ExperimentKey)
		assert.Empty(t, eCtx.ExperimentExecutionId)
	})
}

func TestMapToNetworkFilterExcludeIp(t *testing.T) {
	config.Config.DisableRunc = true

	tests := []struct {
		name         string
		actionConfig map[string]any
		wantExcluded []string
	}{
		{
			name:         "no excludeIp yields no parameter excludes",
			actionConfig: map[string]any{},
			wantExcluded: nil,
		},
		{
			name: "excludeIp CIDRs and IPs are excluded on all ports",
			actionConfig: map[string]any{
				"excludeIp": []any{"10.0.0.0/8", "192.168.1.1"},
			},
			wantExcluded: []string{"10.0.0.0/8 # parameters", "192.168.1.1/32 # parameters"},
		},
		{
			name: "excludeIp composes with include restrictions",
			actionConfig: map[string]any{
				"ip":        []any{"10.0.0.0/8"},
				"excludeIp": []any{"10.1.0.0/16"},
			},
			wantExcluded: []string{"10.1.0.0/16 # parameters"},
		},
		{
			name: "excludeHostname entries are excluded together with excludeIp",
			actionConfig: map[string]any{
				"excludeIp":       []any{"10.0.0.0/8"},
				"excludeHostname": []any{"192.168.1.1"},
			},
			wantExcluded: []string{"10.0.0.0/8 # parameters", "192.168.1.1/32 # parameters"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, _, err := mapToNetworkFilter(context.Background(), nil, netfault.SidecarOpts{}, tt.actionConfig, nil)
			require.NoError(t, err)

			var parameterExcludes []string
			for _, e := range filter.Exclude {
				if e.Comment == "parameters" {
					assert.Equal(t, network.PortRangeAny, e.PortRange)
					parameterExcludes = append(parameterExcludes, e.String())
				}
			}
			assert.Equal(t, tt.wantExcluded, parameterExcludes)

			for _, i := range filter.Include {
				assert.Equal(t, "parameters", i.Comment)
			}
		})
	}
}

func Test_percentageToProbability(t *testing.T) {
	// 0% must map to never (0.0), not always — the whole point of the fix.
	require.Equal(t, 0.0, percentageToProbability(0))
	require.Equal(t, 0.0, percentageToProbability(int64(0)))
	require.Equal(t, 1.0, percentageToProbability(100))
	require.Equal(t, 0.5, percentageToProbability(50))
	require.Equal(t, 0.25, percentageToProbability(25.0))
	// Out-of-range clamps; non-numeric falls back to always.
	require.Equal(t, 1.0, percentageToProbability(150))
	require.Equal(t, 0.0, percentageToProbability(-10))
	require.Equal(t, 1.0, percentageToProbability("nope"))
}

func Test_dependency_hostname_required_and_first(t *testing.T) {
	for _, spec := range []dependencyFaultSpec{latencyFaultSpec, httpAbortFaultSpec, resetFaultSpec} {
		var hostname *action_kit_api.ActionParameter
		for i := range (&dependencyFaultAction{spec: spec}).Describe().Parameters {
			p := (&dependencyFaultAction{spec: spec}).Describe().Parameters[i]
			if p.Name == "hostname" {
				hostname = &p
			}
		}
		require.NotNil(t, hostname, "spec %s missing hostname param", spec.id)
		require.True(t, *hostname.Required, "hostname must be required for %s", spec.id)
		require.Equal(t, 0, *hostname.Order, "hostname must be first (order 0) for %s", spec.id)
	}
}

func Test_dependency_defaultPorts(t *testing.T) {
	require.Equal(t, "80,443", (&dependencyFaultAction{spec: latencyFaultSpec}).defaultPorts())
	require.Equal(t, "80,443", (&dependencyFaultAction{spec: resetFaultSpec}).defaultPorts())
	// HTTP abort is cleartext-only, so 443 is dropped from the default.
	require.Equal(t, "80", (&dependencyFaultAction{spec: httpAbortFaultSpec}).defaultPorts())

	// The Describe()d port parameter default reflects it.
	portDefault := func(a *dependencyFaultAction) string {
		for _, p := range a.Describe().Parameters {
			if p.Name == "port" {
				return *p.DefaultValue
			}
		}
		return ""
	}
	require.Equal(t, "80", portDefault(&dependencyFaultAction{spec: httpAbortFaultSpec}))
	require.Equal(t, "80,443", portDefault(&dependencyFaultAction{spec: latencyFaultSpec}))
}
