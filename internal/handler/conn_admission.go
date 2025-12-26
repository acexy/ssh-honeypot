package handler

import (
	"github.com/acexy/ssh-honeypot/core/types"
)

// ConnAdmissionComponent 默认的 TCP 连接准入控制 允许全部连接接入
type defaultConnAdmissionComponent struct {
}

func (d *defaultConnAdmissionComponent) AllowConn(_ *types.SSHRequest) (allow bool) {
	return true
}

// NewDefaultConnAdmission 创建一个默认的 TCP 链接准入控制
// 允许全部连接接入
func NewDefaultConnAdmission() *defaultConnAdmissionComponent {
	return &defaultConnAdmissionComponent{}
}
