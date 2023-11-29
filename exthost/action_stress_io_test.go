package exthost

import (
	"context"
	"github.com/google/uuid"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/extension-host/exthost/resources"
	extension_kit "github.com/steadybit/extension-kit"
	"github.com/steadybit/extension-kit/extutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestActionIO_Prepare(t *testing.T) {
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	tests := []struct {
		name        string
		requestBody action_kit_api.PrepareActionRequestBody
		wantedError error
		wantedState *resources.StressActionState
	}{
		{
			name: "Should return config",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":            "prepare",
					"duration":          "1000",
					"workers":           "1",
					"path":              "/tmp",
					"mbytes_per_worker": "768",
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedState: &resources.StressActionState{
				StressNGArgs: []string{"--timeout", "1", "--temp-path", "/tmp", "--hdd", "1", "--hdd-bytes", "768m", "--io", "1", "-v"},
				Pid:          0,
			},
		},
		{
			name: "Should return config (flush only)",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":   "prepare",
					"duration": "1000",
					"workers":  "1",
					"path":     "/tmp",
					"mode":     "flush",
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedState: &resources.StressActionState{
				StressNGArgs: []string{"--timeout", "1", "--temp-path", "/tmp", "--io", "1", "-v"},
				Pid:          0,
			},
		},
		{
			name: "Should return config (read_write only)",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":            "prepare",
					"duration":          "1000",
					"workers":           "1",
					"path":              "/tmp",
					"mode":              "read_write",
					"mbytes_per_worker": "1024",
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedState: &resources.StressActionState{
				StressNGArgs: []string{"--timeout", "1", "--temp-path", "/tmp", "--hdd", "1", "--hdd-bytes", "1024m", "-v"},
				Pid:          0,
			},
		},
		{
			name: "Should return error too low duration",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":   "prepare",
					"duration": "500",
					"workers":  "1",
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedError: extension_kit.ToError("Duration must be greater / equal than 1s", nil),
		},
	}
	action := NewStressIOAction()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			state := resources.StressActionState{}
			request := tt.requestBody
			//When
			result, err := action.Prepare(context.Background(), &state, request)

			//Then
			if tt.wantedError != nil && err != nil {
				assert.EqualError(t, err, tt.wantedError.Error())
			} else if tt.wantedError != nil {
				assert.Equal(t, result.Error.Title, tt.wantedError.Error())
			}
			if tt.wantedState != nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantedState.StressNGArgs, state.StressNGArgs)
				assert.Equal(t, tt.wantedState.Pid, state.Pid)
			}
		})
	}
}
