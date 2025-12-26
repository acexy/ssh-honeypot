package types

import "fmt"

type SSHRequest struct {
	ipInfo string

	IP   string
	Port int
}

func (r *SSHRequest) IPInfo() string {
	if r.ipInfo == "" {
		r.ipInfo = fmt.Sprintf("%s:%d", r.IP, r.Port)
	}
	return r.ipInfo
}
