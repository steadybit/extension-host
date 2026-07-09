// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"testing"

	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/steadybit/extension-host/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
