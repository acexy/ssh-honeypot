package internal

import (
	"bytes"
	"io"
	"net"
)

// replayConn 可重复读的包裹连接
// 由于honeypot主动读取过一次客户端版本，ssh核心再次读取会丢失，需要重新封装一个包裹连接
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (r *replayConn) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

// sshServerVersionHijackConn 拦截SSH服务端版本信息连接
// 由于ssh服务端版本由honeypot已经返回给了客户端，ssh核心接手后也会发送一次，为了避免破环协议，需要拦截掉
// ** 这是一个不稳定的操作，如果ssh核心变更了处理逻辑可能会有风险（概率很低，会不遵循ssh协议标准）
type sshServerVersionHijackConn struct {
	net.Conn
	hijacked bool
}

func (s *sshServerVersionHijackConn) Write(p []byte) (int, error) {
	if !s.hijacked && s.isSSHVersionLine(p) {
		s.hijacked = true
		return len(p), nil
	}
	return s.Conn.Write(p)
}

func (s *sshServerVersionHijackConn) isSSHVersionLine(p []byte) bool {
	if len(p) > 256 {
		return false
	}
	if !bytes.HasPrefix(p, []byte("SSH-")) {
		return false
	}
	return bytes.Contains(p, []byte("\n"))
}
