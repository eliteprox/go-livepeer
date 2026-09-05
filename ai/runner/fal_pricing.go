package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultFalUpchargeBps     = 0
	defaultFalPriceDriftPct   = 15.0
	defaultFalPricingInterval = 15 * time.Minute
	falPricingAPI             = "https://api.fal.ai/v1/models/pricing"
)

func operatorUpchargeBps() (int, bool) {
	raw := strings.TrimSpace(os.Getenv("LIVEPEER_FAL_UPCHARGE_BPS"))
	if raw == "" {
		return 0, false
	}
	bps, err := strconv.Atoi(raw)
	if err != nil || bps < 0 {
		return 0, false
	}
	return bps, true
}

func falPriceDriftPct() float64 {
	raw := strings.TrimSpace(os.Getenv("LIVEPEER_FAL_PRICE_DRIFT_PCT"))
	if raw == "" {
		return defaultFalPriceDriftPct
	}
	pct, err := strconv.ParseFloat(raw, 64)
	if err != nil || pct < 0 {
		return defaultFalPriceDriftPct
	}
	return pct
}

func falPricingInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("LIVEPEER_FAL_PRICING_INTERVAL"))
	if raw == "" {
		return defaultFalPricingInterval
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return defaultFalPricingInterval
	}
	return d
}

func falAPIKey() string {
	if key := strings.TrimSpace(os.Getenv("LIVEPEER_FAL_KEY")); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv("FAL_KEY"))
}

func normalizeLiveRunnerSellAndUpstream(priceInfo *LiveRunnerPriceInfo) error {
	if priceInfo.Upstream != nil {
		currency := strings.ToUpper(strings.TrimSpace(priceInfo.Upstream.Currency))
		if currency == "" {
			currency = "USD"
		}
		if !strings.EqualFold(currency, "USD") {
			return fmt.Errorf("price_info.upstream.currency must be USD")
		}
		priceInfo.Upstream.Currency = currency
		priceInfo.Upstream.Provider = strings.TrimSpace(priceInfo.Upstream.Provider)
		priceInfo.Upstream.EndpointID = strings.TrimSpace(priceInfo.Upstream.EndpointID)
		priceInfo.Upstream.Unit = strings.TrimSpace(priceInfo.Upstream.Unit)
		if strings.TrimSpace(priceInfo.Upstream.UnitPrice.String()) != "" {
			if _, err := positiveDecimal(priceInfo.Upstream.UnitPrice, "price_info.upstream.unit_price"); err != nil {
				return err
			}
		}
	}
	if priceInfo.Sell != nil {
		currency := strings.ToUpper(strings.TrimSpace(priceInfo.Sell.Currency))
		if currency == "" {
			currency = "USD"
		}
		if !strings.EqualFold(currency, "USD") {
			return fmt.Errorf("price_info.sell.currency must be USD")
		}
		priceInfo.Sell.Currency = currency
		priceInfo.Sell.Unit = strings.TrimSpace(priceInfo.Sell.Unit)
		if priceInfo.Sell.Unit == "" && priceInfo.Upstream != nil {
			priceInfo.Sell.Unit = priceInfo.Upstream.Unit
		}
		if _, err := positiveDecimal(priceInfo.Sell.Price, "price_info.sell.price"); err != nil {
			return err
		}
		if priceInfo.Sell.UpchargeBps < 0 {
			return fmt.Errorf("price_info.sell.upcharge_bps must be >= 0")
		}
	}
	return nil
}

func applyOperatorUpcharge(priceInfo *LiveRunnerPriceInfo) {
	overlay, overlaySet := operatorUpchargeBps()
	if priceInfo.Sell == nil && priceInfo.Upstream == nil {
		return
	}
	unitPrice, unit, ok := falUnitPrice(*priceInfo)
	if !ok {
		if overlaySet && priceInfo.Sell != nil {
			priceInfo.Sell.UpchargeBps = overlay
		}
		return
	}
	bps := defaultFalUpchargeBps
	if priceInfo.Sell != nil {
		bps = priceInfo.Sell.UpchargeBps
	}
	if overlaySet {
		bps = overlay
	}
	sellPrice := computeSellPrice(unitPrice, bps)
	priceInfo.Sell = &LiveRunnerSellPrice{
		Unit:        unit,
		Price:       json.Number(sellPrice.FloatString(18)),
		Currency:    "USD",
		UpchargeBps: bps,
	}
}

func falUnitPrice(priceInfo LiveRunnerPriceInfo) (*big.Rat, string, bool) {
	if priceInfo.Upstream == nil {
		return nil, "", false
	}
	rat, err := positiveDecimal(priceInfo.Upstream.UnitPrice, "unit_price")
	if err != nil {
		return nil, "", false
	}
	unit := strings.TrimSpace(priceInfo.Upstream.Unit)
	if unit == "" {
		return nil, "", false
	}
	return rat, unit, true
}

func computeSellPrice(unitPrice *big.Rat, upchargeBps int) *big.Rat {
	if upchargeBps < 0 {
		upchargeBps = 0
	}
	factor := new(big.Rat).SetFrac64(int64(10000+upchargeBps), 10000)
	return new(big.Rat).Mul(new(big.Rat).Set(unitPrice), factor)
}

func relativePriceChange(prev, next *big.Rat) float64 {
	if prev == nil || prev.Sign() == 0 || next == nil {
		return 0
	}
	delta := new(big.Rat).Sub(next, prev)
	delta.Abs(delta)
	rel := new(big.Rat).Quo(delta, prev)
	f, _ := rel.Float64()
	return f * 100
}

func positiveDecimal(value json.Number, field string) (*big.Rat, error) {
	raw := strings.TrimSpace(value.String())
	if raw == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	rat, ok := new(big.Rat).SetString(raw)
	if !ok || rat.Sign() <= 0 {
		return nil, fmt.Errorf("%s must be a positive decimal", field)
	}
	return rat, nil
}

func (r *LiveRunnerRegistry) startFalPricingLoop() {
	if r == nil || r.offchain {
		return
	}
	go r.falPricingLoop()
}

func (r *LiveRunnerRegistry) falPricingLoop() {
	interval := falPricingInterval()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-r.stopRegistry:
			return
		case <-timer.C:
			r.refreshFalPrices()
			timer.Reset(falPricingInterval())
		}
	}
}

func (r *LiveRunnerRegistry) refreshFalPrices() {
	key := falAPIKey()
	if key == "" {
		return
	}
	client := r.healthClient
	if client == nil {
		client = http.DefaultClient
	}
	type target struct {
		id         string
		endpointID string
		priceInfo  LiveRunnerPriceInfo
	}
	r.mu.Lock()
	targets := make([]target, 0, len(r.runners))
	for id, live := range r.runners {
		live.mu.Lock()
		endpointID := falEndpointID(live)
		if endpointID != "" {
			targets = append(targets, target{id: id, endpointID: endpointID, priceInfo: live.PriceInfo})
		}
		live.mu.Unlock()
	}
	r.mu.Unlock()

	for _, t := range targets {
		snapshot, err := fetchFalPricing(client, key, t.endpointID)
		if err != nil {
			slog.Warn("fal pricing refresh failed; keeping last good sell price", "runner_id", t.id, "endpoint_id", t.endpointID, "err", err)
			continue
		}
		if err := r.applyFalPricing(t.id, snapshot); err != nil {
			slog.Warn("fal pricing not applied", "runner_id", t.id, "endpoint_id", t.endpointID, "err", err)
		}
	}
}

func falEndpointID(live *liveRunner) string {
	if live.PriceInfo.Upstream != nil && strings.TrimSpace(live.PriceInfo.Upstream.EndpointID) != "" {
		return live.PriceInfo.Upstream.EndpointID
	}
	if strings.TrimSpace(live.Metadata) == "" {
		return ""
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(live.Metadata), &meta); err != nil {
		return ""
	}
	endpoint, _ := meta["endpoint_id"].(string)
	return strings.TrimSpace(endpoint)
}

type falPricingSnapshot struct {
	EndpointID string
	Unit       string
	UnitPrice  *big.Rat
	Currency   string
	FetchedAt  time.Time
}

func fetchFalPricing(client *http.Client, apiKey, endpointID string) (*falPricingSnapshot, error) {
	reqURL, err := url.Parse(falPricingAPI)
	if err != nil {
		return nil, err
	}
	q := reqURL.Query()
	q.Set("endpoint_id", endpointID)
	reqURL.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Key "+apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fal pricing status %d", resp.StatusCode)
	}
	return parseFalPricing(endpointID, body)
}

func parseFalPricing(endpointID string, body []byte) (*falPricingSnapshot, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if nested, ok := raw["pricing"].(map[string]any); ok {
		for k, v := range nested {
			if _, exists := raw[k]; !exists {
				raw[k] = v
			}
		}
	}
	unit := stringField(raw, "unit")
	if unit == "" {
		unit = stringField(raw, "unit_type")
	}
	priceRaw := firstPresent(raw, "unit_price", "price", "unitPrice")
	if unit == "" || priceRaw == "" {
		return nil, fmt.Errorf("fal pricing missing unit or unit_price")
	}
	price, ok := new(big.Rat).SetString(priceRaw)
	if !ok || price.Sign() <= 0 {
		return nil, fmt.Errorf("fal pricing unit_price must be a positive decimal")
	}
	currency := stringField(raw, "currency")
	if currency == "" {
		currency = "USD"
	}
	id := stringField(raw, "endpoint_id")
	if id == "" {
		id = endpointID
	}
	return &falPricingSnapshot{
		EndpointID: id,
		Unit:       unit,
		UnitPrice:  price,
		Currency:   currency,
		FetchedAt:  time.Now().UTC(),
	}, nil
}

func stringField(raw map[string]any, key string) string {
	v, ok := raw[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return strings.TrimSpace(t.String())
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func firstPresent(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if s := stringField(raw, key); s != "" {
			return s
		}
	}
	return ""
}

func (r *LiveRunnerRegistry) applyFalPricing(runnerID string, snapshot *falPricingSnapshot) error {
	if snapshot == nil || snapshot.UnitPrice == nil || snapshot.UnitPrice.Sign() <= 0 {
		return fmt.Errorf("refusing to apply zero fal price")
	}
	live, unlock, err := r.lockLiveRunner(runnerID)
	if err != nil {
		return err
	}
	defer unlock()
	prev, _, hasPrev := falUnitPrice(live.PriceInfo)
	if hasPrev {
		change := relativePriceChange(prev, snapshot.UnitPrice)
		if change > falPriceDriftPct() {
			return fmt.Errorf("fal unit_price jumped %.2f%% over drift cap; keeping last good sell", change)
		}
	}
	live.PriceInfo.Upstream = &LiveRunnerUpstreamPrice{
		Provider:   "fal",
		EndpointID: snapshot.EndpointID,
		Unit:       snapshot.Unit,
		UnitPrice:  json.Number(snapshot.UnitPrice.FloatString(18)),
		Currency:   strings.ToUpper(snapshot.Currency),
		FetchedAt:  snapshot.FetchedAt.Format(time.RFC3339),
	}
	applyOperatorUpcharge(&live.PriceInfo)
	live.updatePriceConverterLocked()
	return nil
}
