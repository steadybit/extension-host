// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_readBiosUuid(t *testing.T) {
	tests := []struct {
		name    string
		content *string
		want    string
	}{
		{name: "vmware", content: new("4203F2B8-1C6A-9E0D-2F41-7A3C55B90E12\n"), want: "4203f2b8-1c6a-9e0d-2f41-7a3c55b90e12"},
		{name: "not set", content: new("00000000-0000-0000-0000-000000000000\n")},
		{name: "not present", content: new("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF\n")},
		{name: "garbage", content: new("Not Settable\n")},
		{name: "missing file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "product_uuid")
			if tt.content != nil {
				assert.NoError(t, os.WriteFile(path, []byte(*tt.content), 0o400))
			}
			assert.Equal(t, tt.want, readBiosUuid(path))
		})
	}
}
