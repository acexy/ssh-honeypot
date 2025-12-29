package core

import (
	"github.com/acexy/golang-toolkit/sys"
	"github.com/acexy/ssh-Honeypot/core/types"
	"github.com/acexy/ssh-Honeypot/internal"
	"github.com/acexy/ssh-Honeypot/internal/component"
)

type honeypot struct {
	h *internal.Honeypot
}

type defaultHoneypotHandler struct {
}

func (d *defaultHoneypotHandler) ConnAdmission() types.ConnAdmissionComponent {
	return component.NewDefaultConnAdmission()
}
func (d *defaultHoneypotHandler) VersionExchange() types.VersionExchangeComponent {
	return component.NewDefaultVersionExchangeComponent()
}

func (d *defaultHoneypotHandler) SSHSettings() types.SSHSettingsComponent {
	return component.NewDefaultSSHSettingsComponent()
}

// NewDefaultSSHConnHandler 创建一个默认的 HoneypotHandler
func NewDefaultSSHConnHandler() *defaultHoneypotHandler {
	return &defaultHoneypotHandler{}
}

func NewHoneypot(handler types.HoneypotHandler) *honeypot {
	return &honeypot{h: internal.NewHoneypot(handler)}
}

func (h *honeypot) Execute() {
	h.h.Execute()
	sys.ShutdownHolding()
}
