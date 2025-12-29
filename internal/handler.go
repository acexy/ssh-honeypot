package internal

import (
	"net"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/golang-toolkit/math/conversion"
	"github.com/acexy/ssh-honeypot/consts"
	"github.com/acexy/ssh-honeypot/core"
	"github.com/acexy/ssh-honeypot/core/types"
	"golang.org/x/crypto/ssh"
)

type honeypot struct {
	listenedIP   string
	listenedPort int

	// 组件
	connAdmission types.ConnAdmissionComponent

	// 版本交互
	versionExchange types.VersionExchangeComponent
	// 组件策略
	allServerVersionStrategies map[string]types.ShowServerVersionStrategy
	allClientVersionStrategies map[string]types.HandleClientVersionStrategy

	// ssh 设置
	sshSettings types.SSHSettingsComponent
	sshConfig   *ssh.ServerConfig
}

func NewHoneypot(handler core.HoneypotHandler) *honeypot {
	if handler == nil {
		logger.Logrus().Fatalln("handler cannot be nil")
	}
	h := honeypot{
		listenedPort: 22,
	}
	h.connAdmission = handler.ConnAdmission()

	h.versionExchange = handler.VersionExchange()
	h.allClientVersionStrategies = h.versionExchange.ClientVersionStrategies()
	h.allServerVersionStrategies = h.versionExchange.ServerVersionStrategies()

	h.sshSettings = handler.SSHSettings()

	h.checkHandler()
	return &h
}

func (h *honeypot) checkHandler() {
	if h.connAdmission == nil {
		logger.Logrus().Fatalln("connAdmission cannot be nil")
	}

	if h.versionExchange == nil {
		logger.Logrus().Fatalln("versionExchange cannot be nil")
	}
	if len(h.allClientVersionStrategies) == 0 {
		logger.Logrus().Fatalln("versionExchange cannot be empty")
	}
	if len(h.allServerVersionStrategies) == 0 {
		logger.Logrus().Fatalln("versionExchange cannot be empty")
	}

	if h.sshSettings == nil {
		logger.Logrus().Fatalln("sshSettings cannot be nil")
	}
}

func (h *honeypot) Execute() {
	l, err := net.Listen("tcp", h.listenedIP+":"+conversion.FromInt(h.listenedPort))
	if err != nil {
		logger.Logrus().Fatalln(err)
	}
	logger.Logrus().Infof("listened: [%d]\n", h.listenedPort)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				logger.Logrus().Errorf("honeypot: [%d] - accept error err=%v", h.listenedPort, err)
				continue
			}
			go h.handleConn(conn)
		}
	}()
}

func (h *honeypot) handleConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	addr := conn.RemoteAddr().(*net.TCPAddr)
	request := &types.SSHRequest{
		IP:   addr.IP.String(),
		Port: addr.Port,
	}
	if !h.doConnAdmission(request) {
		return
	}

	// 返回服务端版本
	serverVersion, allow := h.doVersionExchangeShowServerVersion(conn, request)
	if !allow {
		return
	}

	// 读取客户端版本
	clientVersion, wrappedConn, err := readClientVersion(conn)
	if !h.doVersionExchangeHandleClientVersion(clientVersion, request) {
		_ = connResp(conn, consts.BadClientVersionMessage, 0)
		return
	}
	if err != nil {
		logger.Logrus().Errorf("client: [%s]-> honeypot: [%d] - read client version error err=%v", request.IPInfo(), h.listenedPort, err)
		return
	}
	logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - accepted clientVersion: %s", request.IPInfo(), h.listenedPort, clientVersion)
	wrappedConn = &sshServerVersionHijackConn{
		Conn: wrappedConn,
	}
	sshConn, channels, requests, err := ssh.NewServerConn(wrappedConn, h.getSSHConfig(request, serverVersion))
	if err != nil {
		logger.Logrus().Errorf("client: [%s]-> honeypot: [%d] - ssh error: %v", request.IPInfo(), h.listenedPort, err)
		return
	}
	h.HandleSSHConn(sshConn, channels, requests)
}

func (h *honeypot) getSSHConfig(request *types.SSHRequest, serverVersion string) *ssh.ServerConfig {
	if h.sshConfig != nil {
		return h.sshConfig
	}
	signer, err := ssh.NewSignerFromKey(h.sshSettings.HostKeyPair().PrivateKey())
	if err != nil {
		logger.Logrus().Fatalln("NewSignerFromKey error", err)
	}
	config := &ssh.ServerConfig{
		ServerVersion: serverVersion,
		NoClientAuth:  h.sshSettings.NoAuth(),
		MaxAuthTries:  h.sshSettings.MaxAuthTries(),
	}

	if config.NoClientAuth {
		config.NoClientAuthCallback = func(metadata ssh.ConnMetadata) (*ssh.Permissions, error) {
			logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - accepted: NoClientAuth", request.IPInfo(), h.listenedPort)
			return nil, nil
		}
	} else {
		passwordAuth := h.sshSettings.PasswordAuthStrategy()
		publicAuth := h.sshSettings.PublicKeyAuthStrategy()
		if passwordAuth == nil && publicAuth == nil {
			logger.Logrus().Fatalln("passwordAuth and publicAuth cannot be nil")
		}
		if passwordAuth != nil {
			config.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				pass := string(password)
				logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - password auth: %s", request.IPInfo(), h.listenedPort, pass)
				return passwordAuth.Auth(request, pass)
			}
		}
		if publicAuth != nil {
			config.PublicKeyCallback = func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				fingerprint := ssh.FingerprintLegacyMD5(key)
				logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - pubkey auth: pre check fingerprint: %s", request.IPInfo(), h.listenedPort, fingerprint)
				return publicAuth.KeyPreCheck(request, key)
			}
			config.VerifiedPublicKeyCallback = func(metadata ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, signatureAlgorithm string) (*ssh.Permissions, error) {
				fingerprint := ssh.FingerprintLegacyMD5(key)
				logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - pubkey auth: verify signed data fingerprint: %s", request.IPInfo(), h.listenedPort, fingerprint)
				return publicAuth.VerifySignedData(request, key, permissions, signatureAlgorithm)
			}
		}
	}

	config.AddHostKey(signer)
	return config
}
func (h *honeypot) HandleSSHConn(sshConn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request) {
	// 丢弃全局请求（keepalive 等）
	go ssh.DiscardRequests(requests)
}

// 检查连接权限
func (h *honeypot) doConnAdmission(request *types.SSHRequest) bool {
	allow := h.connAdmission.AllowConn(request)
	if !allow {
		logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - rejected", request.IPInfo(), h.listenedPort)
	}
	return allow
}

// 验证客户端版本
func (h *honeypot) doVersionExchangeHandleClientVersion(clientVersion string, request *types.SSHRequest) bool {
	name, strategy := h.versionExchange.ChooseHandleClientVersionStrategy(request, h.allClientVersionStrategies)
	logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - choose handleClientStrategy: %s", request.IPInfo(), h.listenedPort, name)
	allow := strategy.HandleVersion(request, clientVersion)
	if !allow {
		logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - rejected clientVersion: %s", request.IPInfo(), h.listenedPort, clientVersion)
	}
	return allow
}

// 显示服务端版本
func (h *honeypot) doVersionExchangeShowServerVersion(conn net.Conn, request *types.SSHRequest) (string, bool) {
	name, strategy := h.versionExchange.ChooseShowServerVersionStrategy(request, h.allServerVersionStrategies)
	logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - choose ShowServerVersionStrategy: %s", request.IPInfo(), h.listenedPort, name)
	allow, sec, serverVersion := strategy.ShowVersion(request)
	if !allow {
		logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - rejected", request.IPInfo(), h.listenedPort)
		return serverVersion, allow
	}
	err := connResp(conn, serverVersion, sec)
	if err != nil {
		logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - delay error err=%v", request.IPInfo(), h.listenedPort, err)
		return serverVersion, false
	}
	return serverVersion, allow
}
