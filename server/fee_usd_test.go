package server

import (
	"math/big"
	"testing"
	"time"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/eth"
	"github.com/stretchr/testify/require"
)

func TestComputeFeeUsdSnapshot(t *testing.T) {
	require := require.New(t)

	prev := core.PriceFeedWatcher
	t.Cleanup(func() { core.PriceFeedWatcher = prev })

	// 10 wei at $3000/ETH => 10 * 3000 * 1e6 / 1e18 = 0 (floors to 0 micros)
	core.PriceFeedWatcher = stubPriceFeedWatcher{
		price: eth.PriceData{
			RoundID:   42,
			Price:     big.NewRat(3000, 1),
			UpdatedAt: time.Unix(1_700_000_000, 0),
		},
	}

	snap := computeFeeUsdSnapshot(big.NewRat(10, 1))
	require.Equal("0", snap.ComputedFeeUsdMicros)
	require.Equal("3000.00000000", snap.EthUsdPrice)
	require.Equal(int64(42), snap.EthUsdRoundID)
	require.NotEmpty(snap.EthUsdUpdatedAt)

	// 1e18 wei (1 ETH) at $2500 => 2_500_000_000 micros ($2500)
	core.PriceFeedWatcher = stubPriceFeedWatcher{
		price: eth.PriceData{
			RoundID:   99,
			Price:     big.NewRat(2500, 1),
			UpdatedAt: time.Unix(1_700_000_100, 0),
		},
	}

	snap = computeFeeUsdSnapshot(big.NewRat(weiPerEthInt, 1))
	require.Equal("2500000000", snap.ComputedFeeUsdMicros)
}

func TestComputeFeeUsdSnapshot_WatcherUnavailable(t *testing.T) {
	require := require.New(t)

	prev := core.PriceFeedWatcher
	t.Cleanup(func() { core.PriceFeedWatcher = prev })

	core.PriceFeedWatcher = nil
	snap := computeFeeUsdSnapshot(big.NewRat(1000, 1))
	require.Empty(snap.ComputedFeeUsdMicros)
}
