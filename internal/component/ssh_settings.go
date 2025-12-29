package component

import (
	"github.com/acexy/golang-toolkit/crypto/asymmetric"
	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/ssh-Honeypot/consts"
	"github.com/acexy/ssh-Honeypot/core/types"
	"golang.org/x/crypto/ssh"
)

type defaultSSHSettingsComponent struct {
}

func (d *defaultSSHSettingsComponent) PasswordAuthStrategy() types.SSHPasswordAuthStrategy {
	return &defaultSSHPasswordAuthStrategy{}
}

func (d *defaultSSHSettingsComponent) PublicKeyAuthStrategy() types.SSHPublicKeyAuthStrategy {
	return nil
}

func (d *defaultSSHSettingsComponent) MaxAuthTries() int {
	return 3
}

func (d *defaultSSHSettingsComponent) NoAuth() bool {
	return false
}

func (d *defaultSSHSettingsComponent) HostKeyPair() asymmetric.KeyPair {
	keyPair, err := asymmetric.NewRsaKeyManager(1024).Create()
	if err != nil {
		logger.Logrus().Fatalln("create rsa key pair error:", err)
	}
	return keyPair
}

func NewDefaultSSHSettingsComponent() *defaultSSHSettingsComponent {
	return &defaultSSHSettingsComponent{}
}

type defaultSSHPasswordAuthStrategy struct {
}

func (d *defaultSSHPasswordAuthStrategy) Auth(request *types.SSHRequest, password string) (*ssh.Permissions, error) {
	if password == consts.DefaultPassword {
		logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - accepted: password auth", request.IPInfo(), request.ListenedPort)
		return nil, nil
	}
	logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - rejected: password auth", request.IPInfo(), request.ListenedPort)
	return nil, consts.ErrAuthFailed
}
