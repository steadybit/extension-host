// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkCorruptPackagesContainerAction(r ociruntime.OciRuntime) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		ociRuntime:   r,
		optsProvider: corruptPackages(r),
		optsDecoder:  corruptPackagesDecode,
		description:  getNetworkCorruptPackagesDescription(),
	}
}

func getNetworkCorruptPackagesDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_package_corruption", BaseActionID),
		Label:       "Corrupt Outgoing Packages",
		Description: "Inject corrupt packets by introducing single bit error at a random offset into egress network traffic.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(corruptIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  new("Linux Host"),
		Category:    new("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: append(
			commonNetworkParameters,
			action_kit_api.ActionParameter{
				Name:         "networkCorruption",
				Label:        "Package Corruption",
				Description:  new("How much of the traffic should be corrupted?"),
				Type:         action_kit_api.ActionParameterTypePercentage,
				DefaultValue: new("15"),
				Required:     new(true),
				MinValue:     new(0),
				MaxValue:     new(100),
				Order:        new(1),
			},
			action_kit_api.ActionParameter{
				Name:        "networkInterface",
				Label:       "Network Interface",
				Description: new("Target Network Interface which should be affected. All if none specified."),
				Type:        action_kit_api.ActionParameterTypeStringArray,
				Required:    new(false),
				Advanced:    new(true),
				Order:       new(104),
			},
		),
	}
}

func corruptPackages(r ociruntime.OciRuntime) networkOptsProvider {
	return func(ctx context.Context, sidecar netfault.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (netfault.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}
		corruption := extutil.ToUInt(request.Config["networkCorruption"])

		filter, messages, err := mapToNetworkFilter(ctx, r, sidecar, request.Config, getRestrictedEndpoints(request))
		if err != nil {
			return nil, nil, err
		}

		interfaces := extutil.ToStringArray(request.Config["networkInterface"])
		if len(interfaces) == 0 {
			interfaces, err = netfault.ListNonLoopbackInterfaceNames(ctx, runner(r, sidecar))
			if err != nil {
				return nil, nil, err
			}
		}

		if len(interfaces) == 0 {
			return nil, nil, fmt.Errorf("no network interfaces specified")
		}

		return &netfault.CorruptPackagesOpts{
			Filter:           filter,
			ExecutionContext: mapToExecutionContext(request),
			Corruption:       corruption,
			Interfaces:       interfaces,
		}, messages, nil
	}
}

func corruptPackagesDecode(data json.RawMessage) (netfault.Opts, error) {
	var opts netfault.CorruptPackagesOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}
