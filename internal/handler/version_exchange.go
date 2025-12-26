package handler

import (
	"github.com/acexy/golang-toolkit/util/coll"
	"github.com/acexy/ssh-honeypot/core/types"
)

const serverVersion = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-18.04"

// defaultVersionExchangeComponent 默认的版本交换组件
type defaultVersionExchangeComponent struct {
}

func (d *defaultVersionExchangeComponent) RegisterServerVersionStrategy() map[string]types.ShowServerVersionStrategy {
	return map[string]types.ShowServerVersionStrategy{
		"default":           &defaultShowServerVersionStrategy{},
		"default-delay3sec": &defaultDelay3SecShowServerVersionStrategy{},
	}
}

func (d *defaultVersionExchangeComponent) ChooseShowServerVersionStrategy(_ *types.SSHRequest, strategies map[string]types.ShowServerVersionStrategy) (string, types.ShowServerVersionStrategy) {
	return coll.MapRandomOne(strategies)
}

func (d *defaultVersionExchangeComponent) RegisterClientVersionStrategy() map[string]types.HandleClientVersionStrategy {
	//TODO implement me
	panic("implement me")
}

func (d *defaultVersionExchangeComponent) ChooseHandleClientVersionStrategy(request *types.SSHRequest, strategies map[string]types.HandleClientVersionStrategy) (string, types.HandleClientVersionStrategy) {
	return coll.MapRandomOne(strategies)
}

type defaultShowServerVersionStrategy struct {
}

func (d *defaultShowServerVersionStrategy) ShowVersion(_ *types.SSHRequest) (disconnect bool, delayResponseSec int, serverVersion string) {
	return false, 0, serverVersion
}

type defaultDelay3SecShowServerVersionStrategy struct {
}

func (d *defaultDelay3SecShowServerVersionStrategy) ShowVersion(_ *types.SSHRequest) (disconnect bool, delayResponseSec int, serverVersion string) {
	return false, 3, serverVersion
}
