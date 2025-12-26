package internal

import (
	"net"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/golang-toolkit/math/conversion"
	"github.com/acexy/ssh-honeypot/core"
	"github.com/acexy/ssh-honeypot/core/types"
)

type honeypot struct {
	listenedIP   string
	listenedPort int

	// 组件
	connAdmission   types.ConnAdmissionComponent
	versionExchange types.VersionExchangeComponent

	// 组件策略
	allServerVersionStrategies map[string]types.ShowServerVersionStrategy
	allClientVersionStrategies map[string]types.HandleClientVersionStrategy
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
	request := types.SSHRequest{
		IP:   addr.IP.String(),
		Port: addr.Port,
	}
	if !h.doConnAdmission(&request) {
		return
	}
	clientVersion, wrappedConn, err := readClientVersion(conn)
	if err != nil {
		logger.Logrus().Errorf("client: [%s]-> honeypot: [%d] - read client version error err=%v", request.IPInfo(), h.listenedPort, err)
		return
	}
	if !h.doVersionExchangeHandleClientVersion(clientVersion, &request) {
		return
	}
	wrappedConn = &sshServerVersionHijackConn{
		Conn: wrappedConn,
	}
	logger.Logrus().Infof("client: [%s]-> honeypot: [%d] - accepted clientVersion: %s", request.IPInfo(), h.listenedPort, clientVersion)
	_, allow := h.doVersionExchangeShowServerVersion(wrappedConn, &request)
	if !allow {
		return
	}

	// 交由ssh核心模块处理

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
	logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - allow serverVersion: %s", request.IPInfo(), h.listenedPort, serverVersion)
	err := delayConnResp(conn, serverVersion+"\r\n", sec)
	if err != nil {
		logger.Logrus().Warningf("client: [%s]-> honeypot: [%d] - delay error err=%v", request.IPInfo(), h.listenedPort, err)
		return serverVersion, false
	}
	return serverVersion, allow
}
