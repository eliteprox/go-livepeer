package runner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const DefaultUsageMaxUnits = "1"

// LiveRunnerQuote is an orch-signed settlement rate bound to a manifest.
// The gateway forwards it; it must not invent sell.price or billable units.
type LiveRunnerQuote struct {
	QuoteID          string                   `json:"quote_id"`
	App              string                   `json:"app"`
	ManifestID       string                   `json:"manifest_id"`
	SellPrice        json.Number             `json:"sell_price"`
	SellUnit         string                   `json:"sell_unit"`
	UpchargeBps      int                      `json:"upcharge_bps"`
	WeiPricePerUnit  int64                   `json:"wei_price_per_unit"`
	WeiPixelsPerUnit int64                   `json:"wei_pixels_per_unit"`
	Upstream         *LiveRunnerUpstreamPrice `json:"upstream,omitempty"`
	MaxUnits         json.Number             `json:"max_units"`
	ExpiresAt        int64                   `json:"expires_at"`
	OrchSig          string                   `json:"orch_sig,omitempty"`
}

// LiveRunnerUsageAttestation is orch-signed realized usage for a quote.
type LiveRunnerUsageAttestation struct {
	QuoteID       string      `json:"quote_id"`
	BillableUnits json.Number `json:"billable_units"`
	SellPrice     json.Number `json:"sell_price"`
	CostWei       string      `json:"cost_wei"`
	OrchSig       string      `json:"orch_sig,omitempty"`
}

type quoteSigningPayload struct {
	QuoteID          string                   `json:"quote_id"`
	App              string                   `json:"app"`
	ManifestID       string                   `json:"manifest_id"`
	SellPrice        json.Number             `json:"sell_price"`
	SellUnit         string                   `json:"sell_unit"`
	UpchargeBps      int                      `json:"upcharge_bps"`
	WeiPricePerUnit  int64                   `json:"wei_price_per_unit"`
	WeiPixelsPerUnit int64                   `json:"wei_pixels_per_unit"`
	Upstream         *LiveRunnerUpstreamPrice `json:"upstream,omitempty"`
	MaxUnits         json.Number             `json:"max_units"`
	ExpiresAt        int64                   `json:"expires_at"`
}

type attestationSigningPayload struct {
	QuoteID       string      `json:"quote_id"`
	BillableUnits json.Number `json:"billable_units"`
	SellPrice     json.Number `json:"sell_price"`
	CostWei       string      `json:"cost_wei"`
}

func (q LiveRunnerQuote) SigningBytes() ([]byte, error) {
	return json.Marshal(quoteSigningPayload{
		QuoteID:          q.QuoteID,
		App:              q.App,
		ManifestID:       q.ManifestID,
		SellPrice:        q.SellPrice,
		SellUnit:         q.SellUnit,
		UpchargeBps:      q.UpchargeBps,
		WeiPricePerUnit:  q.WeiPricePerUnit,
		WeiPixelsPerUnit: q.WeiPixelsPerUnit,
		Upstream:         q.Upstream,
		MaxUnits:         q.MaxUnits,
		ExpiresAt:        q.ExpiresAt,
	})
}

func (a LiveRunnerUsageAttestation) SigningBytes() ([]byte, error) {
	return json.Marshal(attestationSigningPayload{
		QuoteID:       a.QuoteID,
		BillableUnits: a.BillableUnits,
		SellPrice:     a.SellPrice,
		CostWei:       a.CostWei,
	})
}

func NewLiveRunnerQuote(app, manifestID string, priceInfo LiveRunnerPriceInfo, expiresAt time.Time) (*LiveRunnerQuote, error) {
	if priceInfo.Sell == nil {
		return nil, nil
	}
	weiPrice, err := priceInfo.Price.Int64()
	if err != nil || weiPrice <= 0 {
		return nil, fmt.Errorf("converted sell price is required to quote")
	}
	maxUnits := json.Number(DefaultUsageMaxUnits)
	upcharge := priceInfo.Sell.UpchargeBps
	sellUnit := strings.TrimSpace(priceInfo.Sell.Unit)
	if sellUnit == "" {
		sellUnit = strings.TrimSpace(priceInfo.Unit)
	}
	id, err := randomQuoteID()
	if err != nil {
		return nil, err
	}
	return &LiveRunnerQuote{
		QuoteID:          id,
		App:              app,
		ManifestID:       manifestID,
		SellPrice:        priceInfo.Sell.Price,
		SellUnit:         sellUnit,
		UpchargeBps:      upcharge,
		WeiPricePerUnit:  weiPrice,
		WeiPixelsPerUnit: 1,
		Upstream:         priceInfo.Upstream,
		MaxUnits:         maxUnits,
		ExpiresAt:        expiresAt.Unix(),
	}, nil
}

func randomQuoteID() (string, error) {
	var buf [10]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "q_" + strings.ToLower(hex.EncodeToString(buf[:])), nil
}

func ParsePositiveRat(value json.Number) (*big.Rat, error) {
	raw := strings.TrimSpace(value.String())
	if raw == "" {
		return nil, fmt.Errorf("missing decimal")
	}
	rat, ok := new(big.Rat).SetString(raw)
	if !ok || rat.Sign() < 0 {
		return nil, fmt.Errorf("invalid decimal %q", raw)
	}
	return rat, nil
}

func CeilRatToInt64(units *big.Rat) int64 {
	if units == nil || units.Sign() <= 0 {
		return 0
	}
	num := new(big.Int).Set(units.Num())
	den := units.Denom()
	quot := new(big.Int).Quo(num, den)
	if new(big.Int).Rem(num, den).Sign() > 0 {
		quot.Add(quot, big.NewInt(1))
	}
	if !quot.IsInt64() {
		return 0
	}
	return quot.Int64()
}

func IsUsagePriced(priceInfo *LiveRunnerPriceInfo) bool {
	if priceInfo == nil {
		return false
	}
	if priceInfo.Sell != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(priceInfo.Unit), LiveRunnerPaymentUnitUsage)
}
