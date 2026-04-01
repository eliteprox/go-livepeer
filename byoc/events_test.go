package byoc

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrchEventAccumulator_AddAndFlush(t *testing.T) {
	acc := newOrchEventAccumulator()

	// Empty flush returns nil
	assert.Nil(t, acc.Flush())

	acc.Add("type_a", map[string]interface{}{"key": "val1"})
	acc.Add("type_b", map[string]interface{}{"key": "val2"})

	events := acc.Flush()
	require.Len(t, events, 2)
	assert.Equal(t, "type_a", events[0].Type)
	assert.Equal(t, "type_b", events[1].Type)

	// Flush drains the accumulator
	assert.Nil(t, acc.Flush())
}

func TestOrchEventAccumulator_ConcurrentAdd(t *testing.T) {
	acc := newOrchEventAccumulator()
	const n = 100

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			acc.Add("type", map[string]interface{}{"i": i})
		}(i)
	}
	wg.Wait()

	events := acc.Flush()
	assert.Len(t, events, n)
}

func TestMarshalOrchEvents(t *testing.T) {
	events := []orchEvent{
		{Type: "foo", Data: map[string]interface{}{"a": 1}},
		{Type: "bar", Data: map[string]interface{}{"b": "x"}},
	}

	raw, err := marshalOrchEvents(events)
	require.NoError(t, err)

	var decoded []orchEvent
	require.NoError(t, json.Unmarshal([]byte(raw), &decoded))
	assert.Len(t, decoded, 2)
	assert.Equal(t, "foo", decoded[0].Type)
	assert.Equal(t, "bar", decoded[1].Type)
}

func TestOrchEventAccumulatorContextRoundTrip(t *testing.T) {
	acc := newOrchEventAccumulator()
	ctx := withOrchEventAccumulator(context.Background(), acc)

	got := orchEventAccumulatorFromCtx(ctx)
	require.NotNil(t, got)

	got.Add("ev", map[string]interface{}{"x": 1})
	events := acc.Flush()
	require.Len(t, events, 1)
	assert.Equal(t, "ev", events[0].Type)
}

func TestOrchEventAccumulatorFromCtx_NilOnMissingKey(t *testing.T) {
	assert.Nil(t, orchEventAccumulatorFromCtx(context.Background()))
}
