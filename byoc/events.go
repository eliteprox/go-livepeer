package byoc

import (
	"context"
	"encoding/json"
	"sync"
)

// orchEvent is a single event accumulated during an orchestrator request handler.
type orchEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// orchEventAccumulator collects orchestrator-side events during a single HTTP
// request so they can be flushed into the X-Livepeer-Events response header
// (Mechanism 2).
type orchEventAccumulator struct {
	mu     sync.Mutex
	events []orchEvent
}

type orchEventAccCtxKey struct{}

func newOrchEventAccumulator() *orchEventAccumulator {
	return &orchEventAccumulator{}
}

func (a *orchEventAccumulator) Add(eventType string, data interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, orchEvent{Type: eventType, Data: data})
}

// Flush returns all accumulated events and resets the slice.
func (a *orchEventAccumulator) Flush() []orchEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.events
	a.events = nil
	return out
}

// MarshalJSON serialises the accumulated events as a JSON array for the
// X-Livepeer-Events response header.
func marshalOrchEvents(events []orchEvent) (string, error) {
	b, err := json.Marshal(events)
	return string(b), err
}

func withOrchEventAccumulator(ctx context.Context, acc *orchEventAccumulator) context.Context {
	return context.WithValue(ctx, orchEventAccCtxKey{}, acc)
}

func orchEventAccumulatorFromCtx(ctx context.Context) *orchEventAccumulator {
	acc, _ := ctx.Value(orchEventAccCtxKey{}).(*orchEventAccumulator)
	return acc
}
