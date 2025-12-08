package byoc

import (
	"math/big"
	"sync"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/livepeer/go-livepeer/core"
)

type sharedBalanceNode interface {
	Node() *core.LivepeerNode
	SharedBalanceLock() *sync.Mutex
}

// compares expected balance with current balance and updates accordingly with the expected balance being the target
// returns the difference and if minimum balance was covered
// also returns if balance was reset to zero because expected was zero
func compareAndUpdateBalance(node sharedBalanceNode, addr ethcommon.Address, id string, expected *big.Rat, minimumBal *big.Rat) (*big.Rat, *big.Rat, bool, bool) {
	lpNode := node.Node()
	sharedBalMtx := node.SharedBalanceLock()
	sharedBalMtx.Lock()
	defer sharedBalMtx.Unlock()

	current := lpNode.Balances.Balance(addr, core.ManifestID(id))
	if current == nil {
		//create a balance of 1 to start tracking
		lpNode.Balances.Debit(addr, core.ManifestID(id), big.NewRat(0, 1))
		current = lpNode.Balances.Balance(addr, core.ManifestID(id))
	}
	if expected == nil {
		expected = big.NewRat(0, 1)
	}
	diff := new(big.Rat).Sub(expected, current)

	if diff.Sign() > 0 {
		lpNode.Balances.Credit(addr, core.ManifestID(id), diff)
	} else {
		lpNode.Balances.Debit(addr, core.ManifestID(id), new(big.Rat).Abs(diff))
	}

	var resetToZero bool
	if expected.Sign() == 0 {
		lpNode.Balances.Debit(addr, core.ManifestID(id), current)

		resetToZero = true
	}

	//get updated balance after changes
	current = lpNode.Balances.Balance(addr, core.ManifestID(id))

	var minimumBalCovered bool
	if current.Cmp(minimumBal) >= 0 {
		minimumBalCovered = true
	}

	return current, diff, minimumBalCovered, resetToZero
}
