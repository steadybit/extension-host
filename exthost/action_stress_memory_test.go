package exthost

import (
	"github.com/google/uuid"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/extension-kit/extutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestActionMemory_Prepare(t *testing.T) {
	mem, _ := getMemory(50)
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	tests := []struct {
		name        string
		requestBody action_kit_api.PrepareActionRequestBody
		wantedError string
		wantedArgs  []string
	}{
		{
			name: "Should return config",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":     "prepare",
					"duration":   1000,
					"percentage": 50,
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedArgs: []string{"--timeout", "1", "--vm", "1", "--vm-bytes", mem, "--vm-hang", "0", "-v"},
		}, {
			name: "Should return error too low duration",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]interface{}{
					"action":     "prepare",
					"duration":   500,
					"percentage": 50,
				},
				ExecutionId: uuid.New(),
				Target: extutil.Ptr(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedError: "duration must be greater / equal than 1s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			request := tt.requestBody
			//When
			opts, err := stressMemory(request)

			//Then
			if tt.wantedError != "" {
				assert.EqualError(t, err, tt.wantedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantedArgs, opts.Args())
			}
		})
	}
}
