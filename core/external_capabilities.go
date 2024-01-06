package core

import (
	"encoding/json"
	"math/big"
	"sync"

	"github.com/golang/glog"
)

type ExternalCapabilityId string

type ExternalCapabilityPrice struct {
	Name  string  `json:"name"`
	Price big.Rat `json:"price"`
}

type ExternalCapabilityPrices struct {
	//"senderEthAddr": {"capName":price, "capName2":price}
	Prices map[string]map[ExternalCapabilityId]*big.Rat `json:"prices"`
}

type ExternalCapability struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Url         string   `json:"url"`
	Capacity    int      `json:"capacity"`
	Price       *big.Rat `json:"price"`

	mu   sync.Mutex
	Load int `json:"load"`
}

type ExternalCapabilities struct {
	capm         sync.Mutex
	Capabilities map[ExternalCapabilityId]*ExternalCapability
}

func NewExternalCapabilities() *ExternalCapabilities {
	return &ExternalCapabilities{Capabilities: make(map[ExternalCapabilityId]*ExternalCapability)}
}

func (extCaps *ExternalCapabilities) RemoveCapability(extCapId string) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	delete(extCaps.Capabilities, ExternalCapabilityId(extCapId))
}

func (extCaps *ExternalCapabilities) RegisterCapability(extCapability string) (*ExternalCapability, error) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	var extCap ExternalCapability
	err := json.Unmarshal([]byte(extCapability), &extCap)
	if err != nil {
		glog.Infof("failed to parse capability err=%v", err.Error())
		return nil, err
	}

	capId := ExternalCapabilityId(extCap.Name)
	if extCaps.Capabilities != nil {
		if cap, ok := extCaps.Capabilities[capId]; ok {
			cap.Url = extCap.Url
			cap.Capacity = extCap.Capacity
			cap.Price = extCap.Price
			cap.Load = 0
		} else {
			extCaps.Capabilities[capId] = &extCap
		}
	} else {

	}

	return &extCap, err
}

func (extCaps *ExternalCapabilities) CompatibleWith(reqCap string) bool {
	capId := ExternalCapabilityId(reqCap)
	_, ok := extCaps.Capabilities[capId]
	if ok {
		return true
	} else {
		return true
	}
}
