// Copyright 2025 steadybit GmbH. All rights reserved.

package exthost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
	"github.com/steadybit/action-kit/go/action_kit_commons/stress"
	"github.com/steadybit/action-kit/go/action_kit_commons/utils"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/extension-host/config"
	"github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extutil"
	"golang.org/x/sync/syncmap"
	"os"
	"os/exec"
	"strings"
	"time"
)

type stressOptsProvider func(request action_kit_api.PrepareActionRequestBody) (stress.Opts, error)

type stressAction struct {
	runc         runc.Runc
	description  action_kit_api.ActionDescription
	optsProvider stressOptsProvider
	stresses     syncmap.Map
}

type StressActionState struct {
	Sidecar         stress.SidecarOpts
	StressOpts      stress.Opts
	ExecutionId     uuid.UUID
	IgnoreExitCodes []int
}

// Make sure action implements all required interfaces
var (
	_ action_kit_sdk.Action[StressActionState]           = (*stressAction)(nil)
	_ action_kit_sdk.ActionWithStatus[StressActionState] = (*stressAction)(nil)
	_ action_kit_sdk.ActionWithStop[StressActionState]   = (*stressAction)(nil) // Optional, needed when the action needs a stop method
)

func newStressAction(
	runc runc.Runc,
	description func() action_kit_api.ActionDescription,
	optsProvider stressOptsProvider,
) action_kit_sdk.Action[StressActionState] {
	return &stressAction{
		description:  description(),
		optsProvider: optsProvider,
		runc:         runc,
		stresses:     syncmap.Map{},
	}
}

func (a *stressAction) NewEmptyState() StressActionState {
	return StressActionState{}
}

// Describe returns the action description for the platform with all required information.
func (a *stressAction) Describe() action_kit_api.ActionDescription {
	return a.description
}

// Prepare is called before the action is started.
// It can be used to validate the parameters and prepare the action.
// It must not cause any harmful effects.
// The passed in state is included in the subsequent calls to start/status/stop.
// So the state should contain all information needed to execute the action and even more important: to be able to stop it.
func (a *stressAction) Prepare(ctx context.Context, state *StressActionState, request action_kit_api.PrepareActionRequestBody) (*action_kit_api.PrepareResult, error) {
	if _, err := CheckTargetHostname(request.Target.Attributes); err != nil {
		return nil, err
	}

	if !isStressNgInstalled() {
		return &action_kit_api.PrepareResult{
			Error: extutil.Ptr(action_kit_api.ActionKitError{
				Title:  "Stress-ng is not installed!",
				Status: extutil.Ptr(action_kit_api.Errored),
			}),
		}, nil
	}

	opts, err := a.optsProvider(request)
	if err != nil {
		return nil, err
	}

	initProcess, err := runc.ReadLinuxProcessInfo(ctx, 1, specs.PIDNamespace, specs.CgroupNamespace)
	if err != nil {
		return nil, extension_kit.ToError("Failed to prepare stress settings.", err)
	}

	adaptCpuHosts(&opts)

	state.StressOpts = opts
	state.Sidecar = stress.SidecarOpts{
		TargetProcess: initProcess,
		IdSuffix:      "host",
		ExecutionId:   request.ExecutionId,
	}
	state.ExecutionId = request.ExecutionId
	if !extutil.ToBool(request.Config["failOnOomKill"]) {
		state.IgnoreExitCodes = []int{137}
	}
	return nil, nil
}

func adaptCpuHosts(s *stress.Opts) {
	if s.CpuWorkers == nil || *s.CpuWorkers != 0 {
		return
	}

	//stress-ng will use all configured processors, we deem this to be wrong and expect all online cpus to be used.
	if c, err := utils.ReadCpusAllowedCount("/proc/1/status"); err == nil {
		s.CpuWorkers = extutil.Ptr(c)
	} else {
		log.Debug().Err(err).Msg("failed to read cpus allowed for pid 1")
	}
}

func (a *stressAction) stress(ctx context.Context, sidecar stress.SidecarOpts, opts stress.Opts) (stress.Stress, error) {
	if config.Config.DisableRunc {
		return stress.NewStressProcess(opts)
	}

	return stress.NewStressRunc(ctx, a.runc, sidecar, opts)
}

func (a *stressAction) Start(ctx context.Context, state *StressActionState) (*action_kit_api.StartResult, error) {
	s, err := a.stress(ctx, state.Sidecar, state.StressOpts)
	if err != nil {
		return nil, extension_kit.ToError("Failed to stress host", err)
	}

	a.stresses.Store(state.ExecutionId, s)

	if err := s.Start(); err != nil {
		return nil, extension_kit.ToError("Failed to stress host", err)
	}

	return &action_kit_api.StartResult{
		Messages: extutil.Ptr([]action_kit_api.Message{
			{
				Level:   extutil.Ptr(action_kit_api.Info),
				Message: fmt.Sprintf("Starting stress host with args %s", strings.Join(state.StressOpts.Args(), " ")),
			},
		}),
	}, nil
}

func (a *stressAction) Status(_ context.Context, state *StressActionState) (*action_kit_api.StatusResult, error) {
	exited, err := a.stressExited(state.ExecutionId)
	if !exited {
		return &action_kit_api.StatusResult{Completed: false}, nil
	}

	if err == nil {
		return &action_kit_api.StatusResult{
			Completed: true,
			Messages: &[]action_kit_api.Message{
				{
					Level:   extutil.Ptr(action_kit_api.Info),
					Message: "Stress host stopped",
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
							Message: fmt.Sprintf("stress-ng exited unexpectedly: %s", errMessage),
						},
					},
				}, nil
			}
		}
	}

	return &action_kit_api.StatusResult{
		Completed: true,
		Error: &action_kit_api.ActionKitError{
			Status: extutil.Ptr(action_kit_api.Errored),
			Title:  fmt.Sprintf("Failed to stress host: %s", errMessage),
		},
	}, nil
}

func (a *stressAction) Stop(_ context.Context, state *StressActionState) (*action_kit_api.StopResult, error) {
	messages := make([]action_kit_api.Message, 0)

	stopped := a.stopStressHost(state.ExecutionId)
	if stopped {
		messages = append(messages, action_kit_api.Message{
			Level:   extutil.Ptr(action_kit_api.Info),
			Message: "Canceled stress host",
		})
	}

	return &action_kit_api.StopResult{
		Messages: &messages,
	}, nil
}

func (a *stressAction) stressExited(executionId uuid.UUID) (bool, error) {
	s, ok := a.stresses.Load(executionId)
	if !ok {
		return true, nil
	}
	return s.(stress.Stress).Exited()
}

func (a *stressAction) stopStressHost(executionId uuid.UUID) bool {
	s, ok := a.stresses.LoadAndDelete(executionId)
	if !ok {
		return false
	}
	s.(stress.Stress).Stop()
	return true
}

func isStressNgInstalled() bool {
	path := utils.LocateExecutable("stress-ng", "STEADYBIT_EXTENSION_STRESSNG_PATH")
	cmd := exec.Command(path, "-V")
	cmd.Dir = os.TempDir()
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer
	err := cmd.Start()
	if err != nil {
		log.Error().Err(err).Msg("failed to Start stress-ng")
		return false
	}
	timer := time.AfterFunc(1*time.Second, func() {
		err := cmd.Process.Kill()
		if err != nil && !strings.Contains(err.Error(), "process already finished") {
			log.Error().Err(err).Msg("failed to kill stress-ng")
			return
		}
	})
	err = cmd.Wait()
	if err != nil {
		log.Error().Err(err).Msg("failed to wait for stress-ng")
		return false
	}
	timer.Stop()
	success := cmd.ProcessState.Success()
	if !success {
		log.Error().Err(err).Msgf("stress-ng is not installed: 'stress-ng -V' in %v returned: %v", os.TempDir(), outputBuffer.Bytes())
	}
	return success
}
