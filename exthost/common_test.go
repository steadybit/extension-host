package exthost

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheckTargetHostname(t *testing.T) {
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	type args struct {
		attributes map[string][]string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Should return error when hostname is not set",
			args: args{
				attributes: map[string][]string{
					"host.hostname": {},
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "Should return error when hostname is empty",
			args: args{
				attributes: map[string][]string{
					"host.hostname": {""},
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "Should return no error",
			args: args{
				attributes: map[string][]string{
					"host.hostname": {"myhostname"},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hn, err := CheckTargetHostname(tt.args.attributes)
			tt.wantErr(t, err, fmt.Sprintf("CheckTargetHostname(%v)", tt.args.attributes))
			if err == nil {
				assert.Equal(t, new("myhostname"), hn)
			}
		})
	}
}
