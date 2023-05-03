// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-container/pkg/networkutils"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkLimitBandwidthContainerAction() action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		optsProvider: limitBandwidth(),
		optsDecoder:  limitBandwidthDecode,
		description:  getNetworkLimitBandwidthDescription(),
	}
}

func getNetworkLimitBandwidthDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_bandwidth", BaseActionID),
		Label:       "Limit Bandwidth",
		Description: "Limit available network bandwidth.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(bandwidthIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         TargetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Category:    extutil.Ptr("network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.External,
		Parameters: append(
			commonNetworkParameters,
			action_kit_api.ActionParameter{
				Name:         "bandwidth",
				Label:        "Network Bandwidth",
				Description:  extutil.Ptr("How much traffic should be allowed per second?"),
				Type:         action_kit_api.Bitrate,
				DefaultValue: extutil.Ptr("1024kbit"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
			},
			action_kit_api.ActionParameter{
				Name:        "networkInterface",
				Label:       "Network Interface",
				Description: extutil.Ptr("Target Network Interface which should be attacked."),
				Type:        action_kit_api.StringArray,
				Required:    extutil.Ptr(false),
				Order:       extutil.Ptr(104),
			},
		),
	}
}

func limitBandwidth() networkOptsProvider {
	return func(ctx context.Context, request action_kit_api.PrepareActionRequestBody) (networkutils.Opts, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, err
		}
		bandwidth := extutil.ToString(request.Config["bandwidth"])

		var restrictedEndpoints []action_kit_api.RestrictedEndpoint
		if request.ExecutionContext != nil && request.ExecutionContext.RestrictedEndpoints != nil {
			restrictedEndpoints = *request.ExecutionContext.RestrictedEndpoints
		}

		filter, err := mapToNetworkFilter(ctx, request.Config, restrictedEndpoints)
		if err != nil {
			return nil, err
		}

		interfaces := extutil.ToStringArray(request.Config["networkInterface"])
		if len(interfaces) == 0 {
			interfaces, err = readNetworkInterfaces(ctx)
			if err != nil {
				return nil, err
			}
		}

		if len(interfaces) == 0 {
			return nil, fmt.Errorf("no network interfaces specified")
		}

		return &networkutils.LimitBandwidthOpts{
			Filter:     filter,
			Bandwidth:  bandwidth,
			Interfaces: interfaces,
		}, nil
	}
}

func limitBandwidthDecode(data json.RawMessage) (networkutils.Opts, error) {
	var opts networkutils.LimitBandwidthOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}
