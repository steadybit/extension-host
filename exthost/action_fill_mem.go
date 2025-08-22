// Copyright 2025 steadybit GmbH. All rights reserved.

package exthost

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/memfill"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	extension_kit "github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"golang.org/x/sync/syncmap"
	"os/exec"
	"time"
)

type fillMemoryAction struct {
	ociRuntime ociruntime.OciRuntime
	memfills   syncmap.Map
}

type FillMemoryActionState struct {
	ExecutionId     uuid.UUID
	TargetProcess   ociruntime.LinuxProcessInfo
	FillMemoryOpts  memfill.Opts
	IgnoreExitCodes []int
}

// Make sure fillMemoryAction implements all required interfaces
var _ action_kit_sdk.Action[FillMemoryActionState] = (*fillMemoryAction)(nil)
var _ action_kit_sdk.ActionWithStop[FillMemoryActionState] = (*fillMemoryAction)(nil)
var _ action_kit_sdk.ActionWithStatus[FillMemoryActionState] = (*fillMemoryAction)(nil)

func NewFillMemoryHostAction(r ociruntime.OciRuntime) action_kit_sdk.Action[FillMemoryActionState] {
	return &fillMemoryAction{
		ociRuntime: r,
	}
}

func (a *fillMemoryAction) NewEmptyState() FillMemoryActionState {
	return FillMemoryActionState{}
}

func (a *fillMemoryAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          fmt.Sprintf("%s.fill_mem", BaseActionID),
		Label:       "Fill Memory",
		Description: "Fills the memory of the host for the given duration.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(fillMemoryIcon),
		TargetSelection: &action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: &targetSelectionTemplates,
		},
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("Resource"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("How long should the memory be filled?"),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
			},
			{
				Name:         "mode",
				Label:        "Mode",
				Description:  extutil.Ptr("*Fill and meet specified usage:* Fill up the memory until the desired usage is met. Memory allocation will be adjusted constantly to meet the target.\n\n*Fill the specified amount:* Allocate and hold the specified amount of Memory."),
				Type:         action_kit_api.ActionParameterTypeString,
				DefaultValue: extutil.Ptr(string(memfill.ModeUsage)),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
				Options: extutil.Ptr([]action_kit_api.ParameterOption{
					action_kit_api.ExplicitParameterOption{
						Label: "Fill and meet specified usage",
						Value: string(memfill.ModeUsage),
					},
					action_kit_api.ExplicitParameterOption{
						Label: "Fill the specified amount",
						Value: string(memfill.ModeAbsolute),
					},
				}),
			},
			{
				Name:         "size",
				Label:        "Size",
				Description:  extutil.Ptr("Percentage of total memory or Megabytes."),
				Type:         action_kit_api.ActionParameterTypeInteger,
				DefaultValue: extutil.Ptr("80"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			},
			{
				Name:         "unit",
				Label:        "Unit",
				Description:  extutil.Ptr("Unit for the size parameter."),
				Type:         action_kit_api.ActionParameterTypeString,
				DefaultValue: extutil.Ptr(string(memfill.UnitPercent)),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(4),
				Options: extutil.Ptr([]action_kit_api.ParameterOption{
					action_kit_api.ExplicitParameterOption{
						Label: "Megabytes",
						Value: string(memfill.UnitMegabyte),
					},
					action_kit_api.ExplicitParameterOption{
						Label: "% of total memory",
						Value: string(memfill.UnitPercent),
					},
				}),
			},
			{
				Name:         "failOnOomKill",
				Label:        "Fail on OOM Kill",
				Description:  extutil.Ptr("Should an OOM kill be considered a failure?"),
				Type:         action_kit_api.ActionParameterTypeBoolean,
				DefaultValue: extutil.Ptr("false"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(5),
			},
		},
	}
}

func fillMemoryOpts(request action_kit_api.PrepareActionRequestBody) (memfill.Opts, error) {
	opts := memfill.Opts{
		Size:         extutil.ToInt(request.Config["size"]),
		Mode:         memfill.Mode(request.Config["mode"].(string)),
		Unit:         memfill.Unit(request.Config["unit"].(string)),
		Duration:     time.Duration(extutil.ToInt64(request.Config["duration"])) * time.Millisecond,
		IgnoreCgroup: true,
	}
	return opts, nil
}

func (a *fillMemoryAction) Prepare(ctx context.Context, state *FillMemoryActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	if _, err := CheckTargetHostname(request.Target.Attributes); err != nil {
		return nil, err
	}

	opts, err := fillMemoryOpts(request)
	if err != nil {
		return nil, err
	}

	initProcess, err := ociruntime.ReadLinuxProcessInfo(ctx, 1, specs.PIDNamespace)
	if err != nil {
		return nil, extension_kit.ToError("Failed to prepare fill memory settings.", err)
	}

	state.TargetProcess = initProcess
	state.FillMemoryOpts = opts
	state.ExecutionId = request.ExecutionId

	if !extutil.ToBool(request.Config["failOnOomKill"]) {
		state.IgnoreExitCodes = []int{137}
	}
	return nil, nil
}

func (a *fillMemoryAction) memfill(targetProcess ociruntime.LinuxProcessInfo, opts memfill.Opts) (memfill.Memfill, error) {
	if config.Config.DisableRunc {
		return memfill.NewMemfillProcess(targetProcess, opts)
	}

	return memfill.NewMemfillProcess(targetProcess, opts)
}

func (a *fillMemoryAction) Start(_ context.Context, state *FillMemoryActionState) (*action_kit_api.StartResult, error) {
	memFill, err := a.memfill(state.TargetProcess, state.FillMemoryOpts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to prepare fill memory on host", err)
	}

	a.memfills.Store(state.ExecutionId, memFill)

	if err := memFill.Start(); err != nil {
		return nil, extension_kit.ToError("Failed to fill memory on host", err)
	}

	return &action_kit_api.StartResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Starting fill memory on host with args %s", memFill.Args()),
			},
		}),
	}, nil
}

func (a *fillMemoryAction) Status(_ context.Context, state *FillMemoryActionState) (*action_kit_api.StatusResult, error) {
	exited, err := a.fillMemoryExited(state.ExecutionId)
	if !exited {
		return &action_kit_api.StatusResult{Completed: false}, nil
	}

	if err == nil {
		return &action_kit_api.StatusResult{
			Completed: true,
			Messages: &[]action_kit_api.Message{
				{
					Level:   extutil.Ptr(action_kit_api.Info),
					Message: "fill memory on host stopped",
				},
			},
		}, nil
	}

	errMessage := err.Error()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode := exitErr.ExitCode()
		if len(exitErr.Stderr) > 0 {
			errMessage = fmt.Sprintf("%s\n%s", exitErr.Error(), string(exitErr.Stderr))
		}

		for _, ignore := range state.IgnoreExitCodes {
			if exitCode == ignore {
				return &action_kit_api.StatusResult{
					Completed: true,
					Messages: &[]action_kit_api.Message{
						{
							Level:   extutil.Ptr(action_kit_api.Warn),
							Message: fmt.Sprintf("memfill exited unexpectedly: %s", errMessage),
						},
					},
				}, nil
			}
		}
	}

	return &action_kit_api.StatusResult{
		Completed: true,
		Error: &action_kit_api.ActionKitError{
			Status: extutil.Ptr(action_kit_api.Failed),
			Title:  fmt.Sprintf("Failed to fill memory on host: %s", errMessage),
		},
	}, nil
}

func (a *fillMemoryAction) Stop(_ context.Context, state *FillMemoryActionState) (*action_kit_api.StopResult, error) {
	messages := make([]action_kit_api.Message, 0)

	if a.stopFillMemoryHost(state.ExecutionId) {
		messages = append(messages, action_kit_api.Message{
			Level:   extutil.Ptr(action_kit_api.Info),
			Message: "Canceled fill memory on host",
		})
	}

	return &action_kit_api.StopResult{
		Messages: &messages,
	}, nil
}

func (a *fillMemoryAction) fillMemoryExited(executionId uuid.UUID) (bool, error) {
	s, ok := a.memfills.Load(executionId)
	if !ok {
		return true, nil
	}
	return s.(memfill.Memfill).Exited()
}

func (a *fillMemoryAction) stopFillMemoryHost(executionId uuid.UUID) bool {
	s, ok := a.memfills.LoadAndDelete(executionId)
	if !ok {
		return false
	}
	err := s.(memfill.Memfill).Stop()
	return err == nil
}
