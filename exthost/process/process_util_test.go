package stopprocess

import (
	"github.com/stretchr/testify/assert"
	"os/exec"
	"testing"
)

func TestStopProcesses(t *testing.T) {
	command := exec.Command("tail", "-f", "/dev/null", "&")
	err := command.Start()
	assert.NoError(t, err)
	ids := FindProcessIds("tail")
	assert.Equal(t, 1, len(ids))
	assert.Equal(t, command.Process.Pid, ids[0])
	err = StopProcesses(ids, true)
	assert.NoError(t, err)
}

func TestStopProcessesSkipsVanishedPid(t *testing.T) {
	command := exec.Command("true")
	assert.NoError(t, command.Start())
	vanishedPid := command.Process.Pid
	assert.NoError(t, command.Wait())

	assert.NotPanics(t, func() {
		err := StopProcesses([]int{vanishedPid}, true)
		assert.NoError(t, err)
	})
}
