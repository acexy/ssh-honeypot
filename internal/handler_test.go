package internal

import (
	"testing"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/golang-toolkit/sys"
	"github.com/acexy/ssh-honeypot/core"
)

func init() {
	logger.EnableConsole(logger.TraceLevel)
}

func TestNewHoneypot(t *testing.T) {
	hp := NewHoneypot(core.NewDefaultSSHConnHandler())
	hp.Execute()
	sys.ShutdownHolding()
}
