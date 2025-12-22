package core

import "net"

type HandlerName string

type Client struct {
	IP         string
	Port       int
	VisitCount int
	Conn       net.Conn
}

type SSHConnHandler interface {
	Name() HandlerName
	Handle(client *Client)
}

type StandardSSHConnHandler interface {
	// ShowServerSSHVersion 显示服务端SSH版本
	ShowServerSSHVersion() (string, bool)
	// HandleClientSSHVersion 处理客户端返回的版本
	HandleClientSSHVersion(version string) bool
}
