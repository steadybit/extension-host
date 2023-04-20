package exthost

import (
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_getDiscoveredTargets(t *testing.T) {
	//given
	os.Setenv("steadybit_label_Foo", "Bar")
	os.Setenv("STEADYBIT_DISCOVERY_ENV_LIST", "MyEnvVar,MyEnvVar2;MyEnvVar3")
	os.Setenv("MyEnvVar", "MyEnvVarValue")
	os.Setenv("MyEnvVar2", "MyEnvVarValue2")
	os.Setenv("MyEnvVar3", "MyEnvVarValue3")
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
	assert.Equal(t, attributes["label.foo"], []string{"Bar"})
	assert.Equal(t, attributes["host.env.myenvvar"], []string{"MyEnvVarValue"})
	assert.Equal(t, attributes["host.env.myenvvar2"], []string{"MyEnvVarValue2"})
	assert.Equal(t, attributes["host.env.myenvvar3"], []string{"MyEnvVarValue3"})
}
