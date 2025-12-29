package main

import (
	"github.com/acexy/ssh-Honeypot/core"
)

func main() {
	core.NewHoneypot(core.NewDefaultSSHConnHandler()).Execute()
}
