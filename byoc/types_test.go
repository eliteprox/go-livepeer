package byoc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlattenBYOCJob_Deterministic(t *testing.T) {
	require := require.New(t)
	in := &BYOCJobSigningInput{
		ID:             "id1",
		Capability:     "text-reversal",
		Request:        `{"text":"hi"}`,
		Parameters:     `{"options_filter":{}}`,
		TimeoutSeconds: 30,
	}
	a := FlattenBYOCJob(in)
	b := FlattenBYOCJob(in)
	require.Equal(a, b)
	require.Greater(len(a), 16+4+4*5)
}

func TestFlattenBYOCJob_DiffersByField(t *testing.T) {
	require := require.New(t)
	base := &BYOCJobSigningInput{
		ID:             "x",
		Capability:     "c",
		Request:        "r",
		Parameters:     "p",
		TimeoutSeconds: 1,
	}
	altID := *base
	altID.ID = "y"
	require.NotEqual(FlattenBYOCJob(base), FlattenBYOCJob(&altID))
}
