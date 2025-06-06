// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package exthost

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	extension_kit "github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewNetworkBlackholeContainerAction(r runc.Runc) action_kit_sdk.Action[NetworkActionState] {
	return &networkAction{
		runc:         r,
		optsProvider: blackhole(r),
		optsDecoder:  blackholeDecode,
		description:  getNetworkBlackholeDescription(),
	}
}

func getNetworkBlackholeDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.network_blackhole", BaseActionID),
		Label:       "Block Traffic",
		Description: "Blocks network traffic (incoming and outgoing).",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(blackHoleIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("Network"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters:  commonNetworkParameters,
	}
}

func blackhole(r runc.Runc) networkOptsProvider {
	return func(ctx context.Context, sidecar network.SidecarOpts, request action_kit_api.PrepareActionRequestBody) (network.Opts, action_kit_api.Messages, error) {
		_, err := CheckTargetHostname(request.Target.Attributes)
		if err != nil {
			return nil, nil, err
		}

		var messages action_kit_api.Messages
		if usesCilium, err := network.HasCiliumIpRoutes(ctx, r, sidecar); err != nil {
			messages = append(messages, action_kit_api.Message{
				Level:   extutil.Ptr(action_kit_api.Warn),
				Message: fmt.Sprintf("Failed to check for Cilium routes: %v", err),
			})
		} else if usesCilium {
			return nil, nil, &extension_kit.ExtensionError{
				Title:  "'Block Traffic' on hosts with cilium installed is not supported.",
				Detail: extutil.Ptr("Try replacing this attack with 'Drop Outgoing Traffic' with a loss of 100%. That affects only outgoing traffic, but should yield similar results."),
			}
		}

		filter, netMessages, err := mapToNetworkFilter(ctx, r, sidecar, request.Config, getRestrictedEndpoints(request))
		if err != nil {
			return nil, nil, err
		}
		messages = append(messages, netMessages...)

		return &network.BlackholeOpts{Filter: filter}, messages, nil
	}
}

func blackholeDecode(data json.RawMessage) (network.Opts, error) {
	var opts network.BlackholeOpts
	err := json.Unmarshal(data, &opts)
	return &opts, err
}
