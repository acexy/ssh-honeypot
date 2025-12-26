package core

import (
	"github.com/acexy/ssh-honeypot/core/types"
	"github.com/acexy/ssh-honeypot/internal/handler"
)

type SSHConnHandler interface {
	ConnAdmission() types.ConnAdmissionComponent
}

type defaultSSHConnHandler struct {
}

func (d *defaultSSHConnHandler) ConnAdmission() types.ConnAdmissionComponent {
	return handler.NewDefaultConnAdmission()
}

// NewDefaultSSHConnHandler 创建一个默认的 SSHConnHandler
func NewDefaultSSHConnHandler() *defaultSSHConnHandler {
	return &defaultSSHConnHandler{}
}
