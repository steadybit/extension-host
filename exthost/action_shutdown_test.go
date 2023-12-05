package exthost

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/extension-host/exthost/shutdown"
	"github.com/steadybit/extension-kit/extutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestActionShutdown_Prepare(t *testing.T) {
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	tests := []struct {
		name        string
		requestBody action_kit_api.PrepareActionRequestBody
		wantedError error
		wantedState *ActionState
	}{
		{
			name: "Should return config",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action": "prepare",
					"reboot": "true",
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedState: &ActionState{
				Reboot:         true,
				ShutdownMethod: SyscallOrSysrq,
			},
		},
	}
	action := NewShutdownAction()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			state := ActionState{}
			request := tt.requestBody

			//When
			result, err := action.Prepare(context.Background(), &state, request)

			//Then
			if tt.wantedError != nil && err != nil {
				assert.EqualError(t, err, tt.wantedError.Error())
			} else if tt.wantedError != nil && result != nil {
				assert.Equal(t, result.Error.Title, tt.wantedError.Error())
			}
			if tt.wantedState != nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantedState.Reboot, state.Reboot)
			}
		})
	}
}

func Test_shutdownAction_Start(t *testing.T) {
	type args struct {
		in0   context.Context
		state *ActionState
	}
	tests := []struct {
		name        string
		args        args
		wantedError string
	}{
		{
			name: "Should return no error when rebooting host via command",
			args: args{
				in0: context.Background(),
				state: &ActionState{
					Reboot:         true,
					ShutdownMethod: Command,
				},
			},
		}, {
			name: "Should return error when rebooting host via command fails",
			args: args{
				in0: context.Background(),
				state: &ActionState{
					Reboot:         true,
					ShutdownMethod: Command,
				},
			},
			wantedError: "Reboot failed",
		}, {
			name: "Should return no error when shutting down host via command",
			args: args{
				in0: context.Background(),
				state: &ActionState{
					Reboot:         false,
					ShutdownMethod: Command,
				},
			},
		}, {
			name: "Should return error when shutting down host via command fails",
			args: args{
				in0: context.Background(),
				state: &ActionState{
					Reboot:         false,
					ShutdownMethod: Command,
				},
			},
			wantedError: "Shutdown failed",
		}, {
			name: "Should return no error when rebooting host via SyscallOrSysrq",
			args: args{
				in0: context.Background(),
				state: &ActionState{
					Reboot:         true,
					ShutdownMethod: SyscallOrSysrq,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &shutdownAction{
				command: newMockApi(tt.wantedError != "", false),
				syscall: newMockApi(tt.wantedError != "", false),
				sysrq:   newMockApi(tt.wantedError != "", false),
			}
			result, err := l.Start(tt.args.in0, tt.args.state)
			if tt.wantedError != "" {
				if err != nil {
					assert.EqualError(t, err, tt.wantedError)
				} else if result != nil && result.Error != nil {
					assert.Equal(t, tt.wantedError, result.Error.Title)
				} else {
					assert.Fail(t, "Expected error but no error or result with error was returned")
				}
			}
		})
	}
}

type mockApi struct {
	shouldError   bool
	cmdExecutable bool
}

func (m *mockApi) Reboot() error {
	log.Debug().Msg("mockApi.Reboot")
	if m.shouldError {
		return fmt.Errorf("error")
	}
	return nil
}

func (m *mockApi) Shutdown() error {
	log.Debug().Msg("mockApi.Shutdown")
	if m.shouldError {
		return fmt.Errorf("error")
	}
	return nil
}

func (m *mockApi) IsShutdownCommandExecutable() bool {
	log.Debug().Msg("mockApi.IsShutdownCommandExecutable")
	return m.cmdExecutable
}
func newMockApi(shouldError bool, cmdExecutable bool) shutdown.Command {
	return &mockApi{shouldError: shouldError, cmdExecutable: cmdExecutable}
}
