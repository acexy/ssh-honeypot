package component

import (
	"strings"

	"github.com/acexy/golang-toolkit/util/coll"
	"github.com/acexy/ssh-honeypot/core/types"
)

const serverVersion = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-18.04"

// defaultVersionExchangeComponent 默认的版本交换组件
type defaultVersionExchangeComponent struct {
}

func NewDefaultVersionExchangeComponent() *defaultVersionExchangeComponent {
	return &defaultVersionExchangeComponent{}
}

func (d *defaultVersionExchangeComponent) ClientVersionStrategies() map[string]types.HandleClientVersionStrategy {
	return map[string]types.HandleClientVersionStrategy{
		"default": &defaultHandleClientVersionStrategy{},
	}
}

func (d *defaultVersionExchangeComponent) ChooseHandleClientVersionStrategy(request *types.SSHRequest, strategies map[string]types.HandleClientVersionStrategy) (string, types.HandleClientVersionStrategy) {
	return coll.MapFirst(strategies)
}

func (d *defaultVersionExchangeComponent) ServerVersionStrategies() map[string]types.ShowServerVersionStrategy {
	return map[string]types.ShowServerVersionStrategy{
		"default":           &defaultShowServerVersionStrategy{},
		"default-delay3sec": &defaultDelay3SecShowServerVersionStrategy{},
	}
}

func (d *defaultVersionExchangeComponent) ChooseShowServerVersionStrategy(_ *types.SSHRequest, strategies map[string]types.ShowServerVersionStrategy) (string, types.ShowServerVersionStrategy) {
	return coll.MapRandomOne(strategies)
}

type defaultHandleClientVersionStrategy struct {
}

func (d *defaultHandleClientVersionStrategy) HandleVersion(_ *types.SSHRequest, clientVersion string) bool {
	return strings.HasPrefix(clientVersion, "SSH-")
}

type defaultShowServerVersionStrategy struct {
}

func (d *defaultShowServerVersionStrategy) ShowVersion(_ *types.SSHRequest) (bool, int, string) {
	return true, 0, serverVersion
}

type defaultDelay3SecShowServerVersionStrategy struct {
}

func (d *defaultDelay3SecShowServerVersionStrategy) ShowVersion(_ *types.SSHRequest) (bool, int, string) {
	return true, 3, serverVersion
}
