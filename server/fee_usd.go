package server

import (
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/core"
)

const weiPerEthInt = int64(1_000_000_000_000_000_000)

type feeUsdSnapshot struct {
	ComputedFeeUsdMicros string
	EthUsdPrice          string
	EthUsdRoundID        int64
	EthUsdUpdatedAt      string
}

// computeFeeUsdSnapshot converts a wei-denominated fee to USD micros using the
// global Chainlink ETH/USD PriceFeedWatcher. Returns empty ComputedFeeUsdMicros
// when the watcher is unavailable; signing must never be blocked on conversion.
func computeFeeUsdSnapshot(fee *big.Rat) feeUsdSnapshot {
	empty := feeUsdSnapshot{ComputedFeeUsdMicros: ""}
	if fee == nil || fee.Sign() <= 0 || core.PriceFeedWatcher == nil {
		return empty
	}

	priceData, err := core.PriceFeedWatcher.Current()
	if err != nil {
		glog.Warningf("Failed to get ETH/USD price for usage metering: %v", err)
		return empty
	}

	if priceData.Price == nil || priceData.Price.Sign() <= 0 {
		glog.Warningf("Invalid ETH/USD price for usage metering")
		return empty
	}

	// Floor to whole wei (matches computed_fee FloatString(0) for integer-valued fees).
	feeWei := new(big.Int).Quo(fee.Num(), fee.Denom())
	if feeWei.Sign() <= 0 {
		return empty
	}

	// ethUsdMicros = floor(priceUsd * 1e6)
	microMultiplier := big.NewRat(1_000_000, 1)
	ethUsdMicrosRat := new(big.Rat).Mul(priceData.Price, microMultiplier)
	ethUsdMicros := new(big.Int).Quo(ethUsdMicrosRat.Num(), ethUsdMicrosRat.Denom())

	weiPerEth := big.NewInt(weiPerEthInt)
	usdMicros := new(big.Int).Mul(feeWei, ethUsdMicros)
	usdMicros.Quo(usdMicros, weiPerEth)

	return feeUsdSnapshot{
		ComputedFeeUsdMicros: usdMicros.String(),
		EthUsdPrice:          priceData.Price.FloatString(8),
		EthUsdRoundID:        priceData.RoundID,
		EthUsdUpdatedAt:      priceData.UpdatedAt.UTC().Format(time.RFC3339),
	}
}
