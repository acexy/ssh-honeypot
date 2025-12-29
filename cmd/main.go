package main

import (
	"github.com/acexy/golang-toolkit/sys"
	"github.com/acexy/ssh-honeypot/core"
	"github.com/acexy/ssh-honeypot/internal"
)

func main() {
	hp := internal.NewHoneypot(core.NewDefaultSSHConnHandler())
	hp.Execute()
	sys.ShutdownHolding()
}
