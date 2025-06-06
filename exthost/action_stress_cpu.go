/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_commons/stress"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewStressCpuAction(r runc.Runc) action_kit_sdk.Action[StressActionState] {
	return newStressAction(r, getStressCpuDescription, stressCpu)
}

func getStressCpuDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.stress-cpu", BaseActionID),
		Label:       "Stress CPU",
		Description: "Generates CPU load for one or more cores.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(stressCPUIcon),
		TargetSelection: extutil.Ptr(action_kit_api.TargetSelection{
			// The target type this action is for
			TargetType: targetID,
			// You can provide a list of target templates to help the user select targets.
			// A template can be used to pre-fill a selection
			SelectionTemplates: &targetSelectionTemplates,
		}),
		Technology: extutil.Ptr("Linux Host"),
		// Category for the targets to appear in
		Category: extutil.Ptr("Resource"),

		// To clarify the purpose of the action, you can set a kind.
		//   Attack: Will cause harm to targets
		//   Check: Will perform checks on the targets
		//   LoadTest: Will perform load tests on the targets
		//   Other
		Kind: action_kit_api.Attack,

		// How the action is controlled over time.
		//   External: The agent takes care and calls stop then the time has passed. Requires a duration parameter. Use this when the duration is known in advance.
		//   Internal: The action has to implement the status endpoint to signal when the action is done. Use this when the duration is not known in advance.
		//   Instantaneous: The action is done immediately. Use this for actions that happen immediately, e.g. a reboot.
		TimeControl: action_kit_api.TimeControlExternal,

		// The parameters for the action
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "cpuLoad",
				Label:        "Host CPU Load",
				Description:  extutil.Ptr("How much CPU should be consumed?"),
				Type:         action_kit_api.Percentage,
				DefaultValue: extutil.Ptr("80"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
				MinValue:     extutil.Ptr(0),
				MaxValue:     extutil.Ptr(100),
			},
			{
				Name:         "workers",
				Label:        "Host CPUs",
				Description:  extutil.Ptr("How many workers should be used to stress the CPU?"),
				Type:         action_kit_api.StressngWorkers,
				DefaultValue: extutil.Ptr("0"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should CPU be stressed?"),
				Type:         action_kit_api.Duration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

func stressCpu(request action_kit_api.PrepareActionRequestBody) (stress.Opts, error) {
	duration := time.Duration(extutil.ToInt64(request.Config["duration"])) * time.Millisecond

	if duration < 1*time.Second {
		return stress.Opts{}, errors.New("duration must be greater / equal than 1s")
	}

	return stress.Opts{
		CpuWorkers: extutil.Ptr(extutil.ToInt(request.Config["workers"])),
		CpuLoad:    extutil.ToInt(request.Config["cpuLoad"]),
		Timeout:    duration,
	}, nil
}
