package runner

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/eth"
)

func TestParseFalPricing(t *testing.T) {
	snapshot, err := parseFalPricing("fal-ai/flux/dev", []byte(`{"endpoint_id":"fal-ai/flux/dev","unit":"image","unit_price":"0.025","currency":"USD"}`))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Unit != "image" || snapshot.UnitPrice.Cmp(big.NewRat(25, 1000)) != 0 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestParseFalPricingNested(t *testing.T) {
	snapshot, err := parseFalPricing("fal-ai/flux/dev", []byte(`{"pricing":{"unit":"image","price":0.025}}`))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Unit != "image" || snapshot.UnitPrice.Sign() <= 0 {
		t.Fatalf("unexpected nested snapshot: %+v", snapshot)
	}
}

func TestRelativePriceChangeRejectsJump(t *testing.T) {
	prev := big.NewRat(25, 1000)
	next := big.NewRat(40, 1000)
	if relativePriceChange(prev, next) <= 15 {
		t.Fatalf("expected a jump over 15%%, got %v", relativePriceChange(prev, next))
	}
}

func TestComputeSellPrice(t *testing.T) {
	sell := computeSellPrice(big.NewRat(25, 1000), 500)
	want := big.NewRat(2625, 100000)
	if sell.Cmp(want) != 0 {
		t.Fatalf("sell=%s want=%s", sell.FloatString(18), want.FloatString(18))
	}
}

func TestQuoteSigningBytesOmitSig(t *testing.T) {
	quote := LiveRunnerQuote{
		QuoteID:          "q_1",
		App:              "app",
		ManifestID:       "mid",
		SellPrice:        json.Number("0.02625"),
		SellUnit:         "image",
		UpchargeBps:      500,
		WeiPricePerUnit:  10,
		WeiPixelsPerUnit: 1,
		MaxUnits:         json.Number("1"),
		ExpiresAt:       1,
		OrchSig:          "0xdead",
	}
	raw, err := quote.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || jsonContainsSig(raw) {
		t.Fatalf("signing payload should omit orch_sig: %s", raw)
	}
}

func jsonContainsSig(raw []byte) bool {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return true
	}
	_, ok := payload["orch_sig"]
	return ok
}

func TestApplyFalPricingRejectsDriftAndKeepsLastGood(t *testing.T) {
	prevWatcher := core.PriceFeedWatcher
	core.PriceFeedWatcher = stubPriceFeedWatcher{price: eth.PriceData{Price: big.NewRat(2000, 1)}}
	defer func() { core.PriceFeedWatcher = prevWatcher }()

	registry := newOnchainLiveRunnerTestRegistry()
	req := liveRunnerTestHeartbeat("runner-drift")
	req.PriceInfo = LiveRunnerPriceInfo{
		Price: json.Number("0.02625"),
		Unit:  "fixed",
		Upstream: &LiveRunnerUpstreamPrice{
			Provider:   "fal",
			EndpointID: "fal-ai/flux/dev",
			Unit:       "image",
			UnitPrice:  json.Number("0.025"),
			Currency:   "USD",
		},
		Sell: &LiveRunnerSellPrice{
			Unit:        "image",
			Price:       json.Number("0.02625"),
			Currency:    "USD",
			UpchargeBps: 500,
		},
	}
	liveRunnerTestRegister(t, registry, req)

	err := registry.applyFalPricing("runner-drift", &falPricingSnapshot{
		EndpointID: "fal-ai/flux/dev",
		Unit:       "image",
		UnitPrice:  big.NewRat(40, 1000),
		Currency:   "USD",
		FetchedAt:  time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected drift cap rejection")
	}

	paymentInfo, err := registry.PaymentInfo("runner-drift")
	if err != nil {
		t.Fatal(err)
	}
	gotSell, ok := new(big.Rat).SetString(paymentInfo.Sell.Price.String())
	if !ok || gotSell.Cmp(big.NewRat(2625, 100000)) != 0 {
		t.Fatalf("expected last-good sell, got %s", paymentInfo.Sell.Price)
	}

	err = registry.applyFalPricing("runner-drift", &falPricingSnapshot{
		EndpointID: "fal-ai/flux/dev",
		Unit:       "image",
		UnitPrice:  big.NewRat(26, 1000),
		Currency:   "USD",
		FetchedAt:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	paymentInfo, err = registry.PaymentInfo("runner-drift")
	if err != nil {
		t.Fatal(err)
	}
	gotSell, ok = new(big.Rat).SetString(paymentInfo.Sell.Price.String())
	want := computeSellPrice(big.NewRat(26, 1000), 500)
	if !ok || gotSell.Cmp(want) != 0 {
		t.Fatalf("expected refreshed sell %s, got %s", want.FloatString(18), paymentInfo.Sell.Price)
	}
}

func TestApplyFalPricingRefusesZero(t *testing.T) {
	registry := newOnchainLiveRunnerTestRegistry()
	err := registry.applyFalPricing("missing", &falPricingSnapshot{UnitPrice: new(big.Rat)})
	if err == nil {
		t.Fatal("expected zero price rejection")
	}
}
