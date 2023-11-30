package exthost

import (
	"github.com/google/uuid"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
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
		wantedError string
		wantedArgs  []string
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

			wantedArgs: []string{"--timeout", "1", "--hdd", "1", "--hdd-bytes", "768m", "--io", "1", "--temp-path", "/tmp", "-v"},
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

			wantedArgs: []string{"--timeout", "1", "--io", "1", "--temp-path", "/tmp", "-v"},
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

			wantedArgs: []string{"--timeout", "1", "--hdd", "1", "--hdd-bytes", "1024m", "--temp-path", "/tmp", "-v"},
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

			wantedError: "duration must be greater / equal than 1s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			request := tt.requestBody
			//When
			opts, err := stressIo(request)

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
