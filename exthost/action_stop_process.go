/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/exthost/process"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
	"sync"
	"time"
)

type stopProcessAction struct {
	processStoppers sync.Map
}

type StopProcessActionState struct {
	ExecutionID   uuid.UUID
	Delay         time.Duration
	ProcessFilter string //pid or executable name
	Graceful      bool
	Deadline      time.Time
	Duration      time.Duration
}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[StopProcessActionState]         = (*stopProcessAction)(nil)
	_ action_kit_sdk.ActionWithStop[StopProcessActionState] = (*stopProcessAction)(nil) // Optional, needed when the action needs a stop method
)

func NewStopProcessAction() action_kit_sdk.Action[StopProcessActionState] {
	return &stopProcessAction{}
}

func (a *stopProcessAction) NewEmptyState() StopProcessActionState {
	return StopProcessActionState{}
}

// Describe returns the action description for the platform with all required information.
func (a *stopProcessAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          stopProcessActionID,
		Label:       "Stop Processes",
		Description: "Stops targeted processes in the given duration.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(stopProcessIcon),
		TargetSelection: extutil.Ptr(action_kit_api.TargetSelection{
			// The target type this action is for
			TargetType: targetID,
			// You can provide a list of target templates to help the user select targets.
			// A template can be used to pre-fill a selection
			SelectionTemplates: extutil.Ptr(targetSelectionTemplates),
		}),
		// Category for the targets to appear in
		Category: extutil.Ptr("State"),

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
				Name:        "process",
				Label:       "Process",
				Description: extutil.Ptr("PID or string to match the process name or command."),
				Type:        action_kit_api.String,
				Required:    extutil.Ptr(true),
				Order:       extutil.Ptr(1),
			},
			{
				Name:         "graceful",
				Label:        "Graceful",
				Description:  extutil.Ptr("If true a TERM signal is sent before the KILL signal."),
				Type:         action_kit_api.Boolean,
				DefaultValue: extutil.Ptr("true"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("Over this period the matching processes are killed."),
				Type:         action_kit_api.Duration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			}, {
				Name:         "delay",
				Label:        "Delay",
				Description:  extutil.Ptr("The delay before the kill signal is sent."),
				Type:         action_kit_api.Duration,
				DefaultValue: extutil.Ptr("5s"),
				Required:     extutil.Ptr(true),
				Advanced:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

// Prepare is called before the action is started.
// It can be used to validate the parameters and prepare the action.
// It must not cause any harmful effects.
// The passed in state is included in the subsequent calls to start/status/stop.
// So the state should contain all information needed to execute the action and even more important: to be able to stop it.
func (a *stopProcessAction) Prepare(_ context.Context, state *StopProcessActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	_, err := CheckTargetHostname(request.Target.Attributes)
	if err != nil {
		return nil, err
	}
	processOrPid := extutil.ToString(request.Config["process"])
	if processOrPid == "" {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Process is required",
				Status: extutil.Ptr(action_kit_api.Errored),
			}),
		}, nil
	}
	state.ProcessFilter = processOrPid

	parsedDuration := extutil.ToUInt64(request.Config["duration"])
	if parsedDuration == 0 {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Duration is required",
				Status: extutil.Ptr(action_kit_api.Errored),
			}),
		}, nil
	}
	duration := time.Duration(parsedDuration) * time.Millisecond
	state.Duration = duration

	parsedDelay := extutil.ToUInt64(request.Config["delay"])
	var delay time.Duration
	if parsedDelay == 0 {
		delay = 0
	} else {
		delay = time.Duration(parsedDelay) * time.Millisecond
	}
	state.Delay = delay

	graceful := extutil.ToBool(request.Config["graceful"])
	state.Graceful = graceful
	return nil, nil
}

// Start is called to start the action
// You can mutate the state here.
// You can use the result to return messages/errors/metrics or artifacts
func (a *stopProcessAction) Start(_ context.Context, state *StopProcessActionState) (*action_kit_api.StartResult, error) {
	stopper := newProcessStopper(state.ProcessFilter, state.Graceful, state.Delay, state.Duration)

	a.processStoppers.Store(state.ExecutionID, stopper)

	stopper.start()
	return &action_kit_api.StartResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Starting stop processes %s", state.ProcessFilter),
			},
		}),
	}, nil
}

// Stop is called to stop the action
// It will be called even if the start method did not complete successfully.
// It should be implemented in a immutable way, as the agent might to retries if the stop method timeouts.
// You can use the result to return messages/errors/metrics or artifacts
func (a *stopProcessAction) Stop(_ context.Context, state *StopProcessActionState) (*action_kit_api.StopResult, error) {
	stopper, ok := a.processStoppers.Load(state.ExecutionID)
	if ok {
		stopper.(*processStopper).stop()
		a.processStoppers.Delete(state.ExecutionID)
	} else {
		log.Debug().Msg("Execution run data not found, stop was already called")
	}
	return nil, nil
}

type processStopper struct {
	stop  func()
	start func()
}

func newProcessStopper(processFilter string, graceful bool, delay, duration time.Duration) *processStopper {
	ctx, cancel := context.WithTimeout(context.Background(), duration)

	start := func() {
		go func() {
			for {
				select {
				case <-time.After(delay):
					pids := stopprocess.FindProcessIds(processFilter)
					log.Debug().Msgf("Found %d processes to stop", len(pids))
					err := stopprocess.StopProcesses(pids, !graceful)
					log.Error().Err(err).Msg("Failed to stop processes")
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	return &processStopper{
		stop:  cancel,
		start: start,
	}
}
