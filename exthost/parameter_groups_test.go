// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"testing"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/stretchr/testify/assert"
)

func groupMembers(desc action_kit_api.ActionDescription) map[string][]string {
	members := map[string][]string{}
	for _, p := range desc.Parameters {
		if p.Group != nil {
			members[*p.Group] = append(members[*p.Group], p.Name)
		}
	}
	return members
}

func parameterOrder(desc action_kit_api.ActionDescription, name string) *int {
	for _, p := range desc.Parameters {
		if p.Name == name {
			return p.Order
		}
	}
	return nil
}

func definedGroups(desc action_kit_api.ActionDescription) []string {
	var names []string
	if desc.ParameterGroups != nil {
		for _, g := range *desc.ParameterGroups {
			names = append(names, g.Name)
		}
	}
	return names
}

func TestParameterGroups(t *testing.T) {
	trafficFilter := []string{"hostname", "ip", "port", "excludeHostname", "excludeIp", "networkInterface"}
	dependencyFilter := []string{"ip", "port", "excludeIp", "attackLocalhost"}

	tests := []struct {
		name    string
		desc    action_kit_api.ActionDescription
		groups  map[string][]string
		defined []string
	}{
		{"blackhole", NewNetworkBlackholeContainerAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: {"hostname", "ip", "port", "excludeHostname", "excludeIp", "blockLocalhost"}}, []string{groupTrafficFilter}},
		{"delay", NewNetworkDelayContainerAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: append(append([]string{}, trafficFilter...), "tcpDataPacketsOnly")}, []string{groupTrafficFilter}},
		{"loss", NewNetworkPackageLossContainerAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: trafficFilter}, []string{groupTrafficFilter}},
		{"corrupt", NewNetworkCorruptPackagesContainerAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: trafficFilter}, []string{groupTrafficFilter}},
		{"bandwidth", NewNetworkLimitBandwidthContainerAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: trafficFilter}, []string{groupTrafficFilter}},
		{"tcpReset", NewNetworkTcpResetAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: {"ip", "port", "excludeHostname", "excludeIp", "networkInterface", "attackLocalhost"}}, []string{groupTrafficFilter}},
		{"dependencyDelay", NewNetworkDelayDependencyAction(nil).Describe(),
			map[string][]string{groupTrafficFilter: dependencyFilter}, []string{groupTrafficFilter}},
		{"dependencyHttpAbort", NewNetworkHttpAbortDependencyAction(nil).Describe(),
			map[string][]string{
				groupResponseDetails: {"responseHeaders", "responseBody", "responseDelay"},
				groupTrafficFilter:   dependencyFilter,
			}, []string{groupTrafficFilter}},
		{"fillDisk", NewFillDiskHostAction(nil).Describe(),
			map[string][]string{groupFillBehavior: {"method", "blocksize"}}, nil},
		{"stopProcess", NewStopProcessAction().Describe(),
			map[string][]string{action_kit_api.ParameterGroupAdditionalSettings: {"delay"}}, nil},
		{"timeTravel", NewTimetravelAction(nil).Describe(),
			map[string][]string{action_kit_api.ParameterGroupAdditionalSettings: {"disableNtp"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Platforms sort parameters by order and show a group where its first parameter is: an explicit
			// "Additional Settings" group must therefore come last, as the platform's fallback does.
			if members, ok := groupMembers(tt.desc)[action_kit_api.ParameterGroupAdditionalSettings]; ok {
				last := tt.desc.Parameters[0]
				for _, p := range tt.desc.Parameters {
					if *p.Order >= *last.Order {
						last = p
					}
				}
				assert.Equal(t, members[len(members)-1], last.Name, "Additional Settings is shown last")
				for _, p := range tt.desc.Parameters {
					if p.Name != members[0] && (p.Group == nil || *p.Group != action_kit_api.ParameterGroupAdditionalSettings) {
						assert.Less(t, *p.Order, *parameterOrder(tt.desc, members[0]), "parameter %s comes before Additional Settings", p.Name)
					}
				}
			}
			assert.Equal(t, tt.groups, groupMembers(tt.desc))
			assert.Equal(t, tt.defined, definedGroups(tt.desc))

			for _, p := range tt.desc.Parameters {
				advanced := p.Advanced != nil && *p.Advanced
				// No advanced parameter is left alone in "Additional Settings" on platforms with groups.
				if advanced {
					assert.NotNil(t, p.Group, "parameter %s", p.Name)
				}
				// Platforms without groups keep showing the filters in "Additional Settings".
				if p.Group != nil && *p.Group == groupTrafficFilter {
					assert.True(t, advanced, "parameter %s", p.Name)
				}
			}
		})
	}
}
