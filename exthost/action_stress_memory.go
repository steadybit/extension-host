/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_commons/stress"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

func NewStressMemoryAction(r runc.Runc) action_kit_sdk.Action[StressActionState] {
	return newStressAction(r, getStressMemoryDescription, stressMemory)
}

func getStressMemoryDescription() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.stress-mem", BaseActionID),
		Label:       "Stress Memory",
		Description: "Allocate a specific amount of memory. Note that this can cause systems to trip the kernel OOM killer on Linux if not enough physical memory and swap is available.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(stressMemoryIcon),
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
				Name:         "percentage",
				Label:        "Load on Host Memory",
				Description:  extutil.Ptr("How much of the total memory should be allocated?"),
				Type:         action_kit_api.Percentage,
				DefaultValue: extutil.Ptr("80"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
				MinValue:     extutil.Ptr(1),
				MaxValue:     extutil.Ptr(100),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should memory be wasted?"),
				Type:         action_kit_api.Duration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
			},
			{
				Name:         "failOnOomKill",
				Label:        "Fail on OOM Kill",
				Description:  extutil.Ptr("Should an OOM kill be considered a failure?"),
				Type:         action_kit_api.Boolean,
				DefaultValue: extutil.Ptr("false"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

func stressMemory(request action_kit_api.PrepareActionRequestBody) (stress.Opts, error) {
	duration := time.Duration(extutil.ToInt64(request.Config["duration"])) * time.Millisecond
	if duration < 1*time.Second {
		return stress.Opts{}, errors.New("duration must be greater / equal than 1s")
	}

	memory, err := getMemory(extutil.ToUInt(request.Config["percentage"]))
	if err != nil {
		return stress.Opts{}, err
	}

	return stress.Opts{
		VmWorkers: extutil.Ptr(1),
		VmBytes:   memory,
		VmHang:    0,
		Timeout:   duration,
	}, nil
}

func getMemory(percentage uint) (string, error) {
	host, err := sysinfo.Host()
	if err != nil {
		return "", err
	}
	memory, err := host.Memory()
	if err != nil {
		return "", err
	}
	result := math.Max(1, float64(percentage)*float64(memory.Total)/100/1024)
	return fmt.Sprintf("%.0fk", result), nil
}
