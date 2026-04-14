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

func NewNetworkPackageLossContainerAction(r ociruntime.OciRuntime) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		ociRuntime:   r,
		optsProvider: packageLoss(r),
		optsDecoder:  packageLossDecode,
		description:  getNetworkPackageLossDescription(),
	}
}

func getNetworkPackageLossDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_package_loss", BaseActionID),
		Label:       "Drop Outgoing Traffic",
		Description: "Cause packet loss for outgoing network traffic (egress).",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        new(lossIcon),
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
				Name:         "percentage",
				Label:        "Network Loss",
				Description:  new("How much of the traffic should be lost?"),
				Type:         action_kit_api.ActionParameterTypePercentage,
				DefaultValue: new("70"),
				Required:     new(true),
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

func packageLoss(r ociruntime.OciRuntime) networkOptsProvider {
	return func(ctx context.Context, sidecar netfault.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (netfault.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}
		loss := extutil.ToUInt(request.Config["percentage"])

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

		return &netfault.PackageLossOpts{
			Filter:           filter,
			ExecutionContext: mapToExecutionContext(request),
			Loss:             loss,
			Interfaces:       interfaces,
		}, messages, nil
	}
}

func packageLossDecode(data json.RawMessage) (netfault.Opts, error) {
	var opts netfault.PackageLossOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}
