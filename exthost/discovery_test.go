package exthost

import (
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_getDiscoveredTargets(t *testing.T) {
	targets := getHostTarget()
	log.Info().Msgf("targets: %+v", targets)
	assert.NotNil(t, targets)
	assert.Len(t, targets, 1)
	target := targets[0]
	assert.NotEmpty(t, target.Id)
	assert.NotEmpty(t, target.Label)
	assert.NotEmpty(t, target.Attributes)
	attributes := target.Attributes
	assert.NotEmpty(t, attributes["host.hostname"])
	assert.NotEmpty(t, attributes["host.domainname"])
	assert.NotEmpty(t, attributes["host.ipv4"])
	assert.NotEmpty(t, attributes["host.nic"])
	assert.NotEmpty(t, attributes["host.os.family"])
	assert.NotEmpty(t, attributes["host.os.manufacturer"])
	assert.NotEmpty(t, attributes["host.os.version"])
}
