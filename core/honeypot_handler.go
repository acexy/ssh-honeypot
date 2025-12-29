package core

import (
	"github.com/acexy/ssh-honeypot/core/types"
	"github.com/acexy/ssh-honeypot/internal/component"
)

type HoneypotHandler interface {
	ConnAdmission() types.ConnAdmissionComponent
	VersionExchange() types.VersionExchangeComponent
	SSHSettings() types.SSHSettingsComponent
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
