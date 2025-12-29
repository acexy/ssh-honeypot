package types

import "fmt"

type HoneypotHandler interface {
	ConnAdmission() ConnAdmissionComponent
	VersionExchange() VersionExchangeComponent
	SSHSettings() SSHSettingsComponent
}

type SSHRequest struct {
	ipInfo string

	ListenedPort int
	// 客户端信息
	IP   string
	Port int
}

func (r *SSHRequest) IPInfo() string {
	if r.ipInfo == "" {
		r.ipInfo = fmt.Sprintf("%s:%d", r.IP, r.Port)
	}
	return r.ipInfo
}
