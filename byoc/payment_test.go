package byoc

import (
	"math/big"
	"sync"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/livepeer/go-livepeer/core"
	"github.com/stretchr/testify/assert"
)

func TestAddressBalances_CompareAndUpdateBalance(t *testing.T) {
	addr := ethcommon.BytesToAddress([]byte("foo"))
	mid := "some_id"
	node := mockJobLivepeerNode()
	node.Balances = core.NewAddressBalances(1 * time.Minute)
	defer node.Balances.StopCleanup()

	assert := assert.New(t)
	bso := &BYOCOrchestratorServer{
		node:         node,
		sharedBalMtx: &sync.Mutex{},
	}
	// Test 1: Balance doesn't exist - should initialize to 1 and then update to expected
	expected := big.NewRat(10, 1)
	minimumBal := big.NewRat(5, 1)
	current, diff, minimumBalCovered, resetToZero := compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to expected value")
	assert.Zero(big.NewRat(10, 1).Cmp(diff), "Diff should be expected - initial (10 - 1)")
	assert.True(minimumBalCovered, "Minimum balance should be covered when going from 1 to 10")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 2: Expected > Current (Credit scenario)
	expected = big.NewRat(20, 1)
	minimumBal = big.NewRat(15, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to expected value")
	assert.Zero(big.NewRat(10, 1).Cmp(diff), "Diff should be 20 - 10 = 10")
	assert.True(minimumBalCovered, "Minimum balance should be covered when crossing threshold")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 3: Expected < Current (Debit scenario)
	expected = big.NewRat(5, 1)
	minimumBal = big.NewRat(3, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to expected value")
	assert.Zero(big.NewRat(-15, 1).Cmp(diff), "Diff should be 5 - 20 = -15")
	assert.True(minimumBalCovered, "Minimum balance should still be covered")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 4: Expected == Current (No change)
	expected = big.NewRat(5, 1)
	minimumBal = big.NewRat(3, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should remain the same")
	assert.Zero(big.NewRat(0, 1).Cmp(diff), "Diff should be 0")
	assert.True(minimumBalCovered, "Minimum balance should still be covered")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 5: Reset to zero (current > 0, expected = 0)
	bso.node.Balances.Credit(addr, core.ManifestID(mid), big.NewRat(5, 1)) // Set current to 10
	expected = big.NewRat(0, 1)
	minimumBal = big.NewRat(3, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be reset to zero")
	assert.Zero(big.NewRat(-10, 1).Cmp(diff), "Diff should be 0 - 10 = -10")
	assert.False(minimumBalCovered, "Minimum balance should not be covered when resetting to zero")
	assert.True(resetToZero, "Should be marked as reset to zero")

	// Test 6: Minimum balance covered threshold - just below to just above
	expected = big.NewRat(2, 1)
	minimumBal = big.NewRat(5, 1)
	compareAndUpdateBalance(bso, addr, mid, expected, minimumBal) // Set to 2

	expected = big.NewRat(5, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to 5")
	assert.Zero(big.NewRat(3, 1).Cmp(diff), "Diff should be 5 - 2 = 3")
	assert.True(minimumBalCovered, "Minimum balance should be covered when crossing from below to at threshold")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 7: Minimum balance not covered - already above threshold
	expected = big.NewRat(10, 1)
	minimumBal = big.NewRat(5, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to 10")
	assert.Zero(big.NewRat(5, 1).Cmp(diff), "Diff should be 10 - 5 = 5")
	assert.True(minimumBalCovered, "Minimum balance should still be covered")
	assert.False(resetToZero, "Should not be reset to zero")

	// Test 8: Negative balance handling
	bso.node.Balances.Debit(addr, core.ManifestID(mid), big.NewRat(20, 1)) // Force negative: 10 - 20 = -10
	expected = big.NewRat(5, 1)
	minimumBal = big.NewRat(3, 1)
	current, diff, minimumBalCovered, resetToZero = compareAndUpdateBalance(bso, addr, mid, expected, minimumBal)

	assert.Zero(expected.Cmp(current), "Balance should be updated to expected value")
	assert.Zero(big.NewRat(15, 1).Cmp(diff), "Diff should be 5 - (-10) = 15")
	assert.True(minimumBalCovered, "Minimum balance should be covered when going from negative to positive above minimum")
	assert.False(resetToZero, "Should not be reset to zero")
}
