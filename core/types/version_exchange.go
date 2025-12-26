package types

// VersionExchangeComponent 控制 SSH 版本交换阶段
type VersionExchangeComponent interface {

	// ClientVersionStrategies 注册检查客户端版本处理策略
	ClientVersionStrategies() map[string]HandleClientVersionStrategy

	// ChooseHandleClientVersionStrategy 注册选择客户端版本处理策略方法
	ChooseHandleClientVersionStrategy(request *SSHRequest, strategies map[string]HandleClientVersionStrategy) (string, HandleClientVersionStrategy)

	// ServerVersionStrategies 注册响应服务端版本处理的所有策略
	ServerVersionStrategies() map[string]ShowServerVersionStrategy

	// ChooseShowServerVersionStrategy 注册选择服务端版本处理策略方法
	ChooseShowServerVersionStrategy(request *SSHRequest, strategies map[string]ShowServerVersionStrategy) (string, ShowServerVersionStrategy)
}

// HandleClientVersionStrategy 检查客户端版本处理策略
type HandleClientVersionStrategy interface {
	HandleVersion(request *SSHRequest, clientVersion string) (allow bool)
}

// ShowServerVersionStrategy 描述服务端版本处理策略
type ShowServerVersionStrategy interface {
	// ShowVersion 响应服务端版本
	// delayResponseSec >= 0时 将执行延迟响应
	ShowVersion(request *SSHRequest) (allow bool, delayResponseSec int, serverVersion string)
}
