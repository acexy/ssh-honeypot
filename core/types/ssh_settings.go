package types

import (
	"github.com/acexy/golang-toolkit/crypto/asymmetric"
	"golang.org/x/crypto/ssh"
)

// SSHSettingsComponent 描述 SSH 设置
type SSHSettingsComponent interface {
	// HostKeyPair 提供主机私钥管理器
	HostKeyPair() asymmetric.KeyPair

	// NoAuth 是否无需认证
	NoAuth() bool

	// MaxAuthTries 最大认证尝试次数
	MaxAuthTries() int

	// PasswordAuthStrategy 密码验证策略
	PasswordAuthStrategy() SSHPasswordAuthStrategy

	// PublicKeyAuthStrategy 公钥验证策略
	PublicKeyAuthStrategy() SSHPublicKeyAuthStrategy
}

// SSHPasswordAuthStrategy SSH密码登录
type SSHPasswordAuthStrategy interface {
	// Auth 账户密码认证
	Auth(request *SSHRequest, password string) (*ssh.Permissions, error)
}

// SSHPublicKeyAuthStrategy SSH公钥登录
type SSHPublicKeyAuthStrategy interface {
	// KeyPreCheck 公钥预检查
	KeyPreCheck(request *SSHRequest, publicKey ssh.PublicKey) (*ssh.Permissions, error)
	// VerifySignedData 验证客户端签名的数据
	VerifySignedData(request *SSHRequest, key ssh.PublicKey, permissions *ssh.Permissions, signatureAlgorithm string) (*ssh.Permissions, error)
}
