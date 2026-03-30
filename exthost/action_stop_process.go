// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	stopprocess "github.com/steadybit/extension-host/exthost/process"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/extutil"
)

type stopProcessAction struct {
	processStoppers sync.Map
}

type StopProcessActionState struct {
	ExecutionId   uuid.UUID
	Delay         time.Duration
	ProcessFilter string //pid or executable name
	Graceful      bool
	Deadline      time.Time
	Duration      time.Duration
}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[StopProcessActionState]           = (*stopProcessAction)(nil)
	_ action_kit_sdk.ActionWithStatus[StopProcessActionState] = (*stopProcessAction)(nil)
	_ action_kit_sdk.ActionWithStop[StopProcessActionState]   = (*stopProcessAction)(nil)
)

func NewStopProcessAction() action_kit_sdk.Action[StopProcessActionState] {
	return &stopProcessAction{}
}

func (a *stopProcessAction) NewEmptyState() StopProcessActionState {
	return StopProcessActionState{}
}

func (a *stopProcessAction) Describe() action_kit_api.ActionDescription {
	return action_kit_api.ActionDescription{
		Id:          stopProcessActionID,
		Label:       "Stop Processes",
		Description: "Stops targeted processes in the given duration.",
		Version:     extbuild.GetSemverVersionStringOrUnknown(),
		Icon:        extutil.Ptr(stopProcessIcon),
		TargetSelection: extutil.Ptr(action_kit_api.TargetSelection{
			TargetType:         targetID,
			SelectionTemplates: extutil.Ptr(targetSelectionTemplates),
		}),
		Technology:  extutil.Ptr("Linux Host"),
		Category:    extutil.Ptr("State"),
		Kind:        action_kit_api.Attack,
		TimeControl: action_kit_api.TimeControlExternal,
		Parameters: []action_kit_api.ActionParameter{
			{
				Name:        "process",
				Label:       "Process",
				Description: extutil.Ptr("PID or string to match the process name or command."),
				Type:        action_kit_api.ActionParameterTypeString,
				Required:    extutil.Ptr(true),
				Order:       extutil.Ptr(1),
			},
			{
				Name:         "graceful",
				Label:        "Graceful",
				Description:  extutil.Ptr("If true a TERM signal is sent before the KILL signal."),
				Type:         action_kit_api.ActionParameterTypeBoolean,
				DefaultValue: extutil.Ptr("true"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(2),
			},
			{
				Name:         "duration",
				Label:        "Duration",
				Description:  extutil.Ptr("Over this period the matching processes are killed."),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: extutil.Ptr("30s"),
				Required:     extutil.Ptr(true),
				Order:        extutil.Ptr(3),
			}, {
				Name:         "delay",
				Label:        "Delay",
				Description:  extutil.Ptr("The delay before the kill signal is sent."),
				Type:         action_kit_api.ActionParameterTypeDuration,
				DefaultValue: extutil.Ptr("5s"),
				Required:     extutil.Ptr(true),
				Advanced:     extutil.Ptr(true),
				Order:        extutil.Ptr(1),
			},
		},
		Stop: extutil.Ptr(action_kit_api.MutatingEndpointReference{}),
	}
}

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
	state.ExecutionId = request.ExecutionId
	return nil, nil
}

func (a *stopProcessAction) Start(_ context.Context, state *StopProcessActionState) (*action_kit_api.StartResult, error) {
	stopper := newProcessStopper(state.ProcessFilter, state.Graceful, state.Delay, state.Duration)

	a.processStoppers.Store(state.ExecutionId, stopper)

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

func (a *stopProcessAction) Status(_ context.Context, state *StopProcessActionState) (*action_kit_api.StatusResult, error) {
	stopper, ok := a.processStoppers.Load(state.ExecutionId)
	if !ok {
		return &action_kit_api.StatusResult{Completed: true}, nil
	}

	s := stopper.(*processStopper)

	if errPtr := s.err.Load(); errPtr != nil {
		return &action_kit_api.StatusResult{
			Completed: true,
			Error: &action_kit_api.ActionKitError{
				Title:  (*errPtr).Error(),
				Status: extutil.Ptr(action_kit_api.Failed),
			},
		}, nil
	}

	return &action_kit_api.StatusResult{Completed: false}, nil
}

func (a *stopProcessAction) Stop(_ context.Context, state *StopProcessActionState) (*action_kit_api.StopResult, error) {
	stopper, ok := a.processStoppers.Load(state.ExecutionId)
	if ok {
		stopper.(*processStopper).cancel()
		a.processStoppers.Delete(state.ExecutionId)
	} else {
		log.Debug().Msg("Execution run data not found, stop was already called")
	}
	return nil, nil
}

type processStopper struct {
	cancel func()
	start  func()
	err    atomic.Pointer[error]
}

func newProcessStopper(processFilter string, graceful bool, delay, duration time.Duration) *processStopper {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	s := &processStopper{
		cancel: cancel,
	}

	s.start = func() {
		go func() {
			defer cancel()
			for {
				select {
				case <-time.After(delay):
					pids := stopprocess.FindProcessIds(processFilter)
					log.Debug().Msgf("Found %d processes to stop", len(pids))
					err := stopprocess.StopProcesses(pids, !graceful)
					if err != nil {
						log.Error().Err(err).Msg("Failed to stop processes")
						s.err.Store(&err)
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	return s
}
