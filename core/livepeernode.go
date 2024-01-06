/*
Core contains the main functionality of the Livepeer node.

The logical orgnization of the `core` module is as follows:

livepeernode.go: Main struct definition and code that is common to all node types.
broadcaster.go: Code that is called only when the node is in broadcaster mode.
orchestrator.go: Code that is called only when the node is in orchestrator mode.
*/
package core

import (
	"errors"
	"math/big"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/pm"

	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/eth"
	lpmon "github.com/livepeer/go-livepeer/monitor"
)

var ErrTranscoderAvail = errors.New("ErrTranscoderUnavailable")
var ErrTranscode = errors.New("ErrTranscode")

// LivepeerVersion node version
// content of this constant will be set at build time,
// using -ldflags, combining content of `VERSION` file and
// output of the `git describe` command.
var LivepeerVersion = "undefined"

var MaxSessions = 10

type NodeType int

const (
	DefaultNode NodeType = iota
	BroadcasterNode
	OrchestratorNode
	TranscoderNode
	RedeemerNode
)

var nodeTypeStrs = map[NodeType]string{
	DefaultNode:      "default",
	BroadcasterNode:  "broadcaster",
	OrchestratorNode: "orchestrator",
	TranscoderNode:   "transcoder",
	RedeemerNode:     "redeemer",
}

func (t NodeType) String() string {
	str, ok := nodeTypeStrs[t]
	if !ok {
		return "unknown"
	}
	return str
}

// LivepeerNode handles videos going in and coming out of the Livepeer network.
type LivepeerNode struct {

	// Common fields
	Eth      eth.LivepeerEthClient
	WorkDir  string
	NodeType NodeType
	Database *common.DB

	// Transcoder public fields
	SegmentChans         map[ManifestID]SegmentChan
	Recipient            pm.Recipient
	SelectionAlgorithm   common.SelectionAlgorithm
	OrchestratorPool     common.OrchestratorPool
	OrchPerfScore        *common.PerfScore
	OrchSecret           string
	Transcoder           Transcoder
	TranscoderManager    *RemoteTranscoderManager
	Balances             *AddressBalances
	Capabilities         *Capabilities
	ExternalCapabilities *ExternalCapabilities
	AutoAdjustPrice      bool
	AutoSessionLimit     bool
	// Broadcaster public fields
	Sender pm.Sender

	// Thread safety for config fields
	mu             sync.RWMutex
	StorageConfigs map[string]*transcodeConfig
	storageMutex   *sync.RWMutex
	// Transcoder private fields
	priceInfo    map[string]*big.Rat
	jobPriceInfo *ExternalCapabilityPrices
	serviceURI   url.URL
	segmentMutex *sync.RWMutex
}

// NewLivepeerNode creates a new Livepeer Node. Eth can be nil.
func NewLivepeerNode(e eth.LivepeerEthClient, wd string, dbh *common.DB) (*LivepeerNode, error) {
	rand.Seed(time.Now().UnixNano())
	//add default capabilities price
	extCapPrices := &ExternalCapabilityPrices{Prices: make(map[string]map[ExternalCapabilityId]*big.Rat)}
	extCapPrices.Prices["default"] = make(map[ExternalCapabilityId]*big.Rat)
	extCapPrices.Prices["default"]["default"] = big.NewRat(1, 1)

	return &LivepeerNode{
		Eth:                  e,
		WorkDir:              wd,
		Database:             dbh,
		AutoAdjustPrice:      true,
		SegmentChans:         make(map[ManifestID]SegmentChan),
		segmentMutex:         &sync.RWMutex{},
		Capabilities:         &Capabilities{capacities: map[Capability]int{}},
		ExternalCapabilities: NewExternalCapabilities(),
		priceInfo:            make(map[string]*big.Rat),
		jobPriceInfo:         extCapPrices,
		StorageConfigs:       make(map[string]*transcodeConfig),
		storageMutex:         &sync.RWMutex{},
	}, nil
}

func (n *LivepeerNode) GetServiceURI() *url.URL {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return &n.serviceURI
}

func (n *LivepeerNode) SetServiceURI(newUrl *url.URL) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.serviceURI = *newUrl
}

// SetBasePrice sets the base price for an orchestrator on the node
func (n *LivepeerNode) SetBasePrice(b_eth_addr string, price *big.Rat) {
	addr := strings.ToLower(b_eth_addr)
	n.mu.Lock()
	defer n.mu.Unlock()

	n.priceInfo[addr] = price
}

// GetBasePrice gets the base price for an orchestrator
func (n *LivepeerNode) GetBasePrice(b_eth_addr string) *big.Rat {
	addr := strings.ToLower(b_eth_addr)
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.priceInfo[addr]
}

func (n *LivepeerNode) GetBasePrices() map[string]*big.Rat {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.priceInfo
}

// SetMaxFaceValue sets the faceValue upper limit for tickets received
func (n *LivepeerNode) SetMaxFaceValue(maxfacevalue *big.Int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.Recipient.SetMaxFaceValue(maxfacevalue)
}

func (n *LivepeerNode) SetMaxSessions(s int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	MaxSessions = s

	//update metrics reporting
	if lpmon.Enabled {
		lpmon.MaxSessions(MaxSessions)
	}

	glog.Infof("Updated session limit to %d", MaxSessions)
}

func (n *LivepeerNode) GetCurrentCapacity() int {
	n.TranscoderManager.RTmutex.Lock()
	defer n.TranscoderManager.RTmutex.Unlock()
	_, totalCapacity, _ := n.TranscoderManager.totalLoadAndCapacity()
	return totalCapacity
}

func (n *LivepeerNode) SetPriceForExternalCapability(senderEthAddress string, extCapId string, price *big.Rat) error {
	//check if sender exists in specific external capability pricing,
	if _, ok := n.jobPriceInfo.Prices[senderEthAddress]; !ok {
		n.jobPriceInfo.Prices[senderEthAddress] = make(map[ExternalCapabilityId]*big.Rat)
	}

	capId := ExternalCapabilityId(extCapId)
	_, ok := n.ExternalCapabilities.Capabilities[capId]
	if !ok {
		return errors.New("no capability exists")
	}

	n.jobPriceInfo.Prices[senderEthAddress][capId] = price

	return nil

}

func (n *LivepeerNode) GetPriceForExternalCapability(senderEthAddress string, extCapId string) *big.Rat {
	n.mu.RLock()
	defer n.mu.RUnlock()
	capId := ExternalCapabilityId(extCapId)
	senderPrices, ok := n.jobPriceInfo.Prices[senderEthAddress]
	if !ok {
		senderPrices = n.jobPriceInfo.Prices["default"]
	}

	if extCapInfo, ok := senderPrices[capId]; ok {
		return extCapInfo
	}

	return nil
}

func (n *LivepeerNode) GetPriceForJob(senderEthAddress string, extCapId string) *big.Rat {
	n.mu.RLock()
	defer n.mu.RUnlock()
	capId := ExternalCapabilityId(extCapId)
	senderPrices, ok := n.jobPriceInfo.Prices[senderEthAddress]
	if !ok {
		return nil //jobPriceInfo in orchestrator checks for nil
	}

	jobPrice := big.NewRat(0, 1)

	if extCapPrice, ok := senderPrices[capId]; ok {

		jobPrice = new(big.Rat).Add(extCapPrice, jobPrice)
	} else {
		//if price not set for sender fall back to default price
		if extCapDefPrice, ok := n.jobPriceInfo.Prices["default"][capId]; ok {
			jobPrice = new(big.Rat).Add(extCapDefPrice, jobPrice)
		}
	}

	return jobPrice
}
