// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const productUuidPath = "/sys/class/dmi/id/product_uuid"

// The file is only readable by root; the extension reads it through CAP_DAC_OVERRIDE.
var biosUuid = sync.OnceValue(func() string {
	return readBiosUuid(productUuidPath)
})

func readBiosUuid(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("BIOS UUID not available")
		return ""
	}
	return normalizeBiosUuid(string(content))
}

// normalizeBiosUuid drops the placeholders firmware reports when no UUID is set (SMBIOS spec 7.2.1).
func normalizeBiosUuid(s string) string {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil || id == uuid.Nil || id == uuid.Max {
		return ""
	}
	return id.String()
}
