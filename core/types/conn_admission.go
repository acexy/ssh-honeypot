package types

import "net"

// ConnAdmission 决定一个 TCP 连接是否允许进入 SSH 流程
type ConnAdmission interface {
	// AllowConn 是否允许该连接继续
	// 返回 false 表示立即断开
	AllowConn(remote net.Addr) (allow bool)
}
