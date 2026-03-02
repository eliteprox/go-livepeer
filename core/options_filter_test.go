package core

import "testing"

func TestEvaluateOptions(t *testing.T) {
	workerOptions := map[string]interface{}{
		"model":        "llama-3",
		"vram_gb":      24.0,
		"cuda_enabled": true,
		"rtt_ms":       "1200",
	}

	tests := []struct {
		name     string
		filter   map[string]string
		expected bool
	}{
		{name: "Empty filter passes", filter: map[string]string{}, expected: true},
		{name: "Exact string passes", filter: map[string]string{"model": "llama-3"}, expected: true},
		{name: "Exact string case insensitive passes", filter: map[string]string{"model": "LLaMA-3"}, expected: true},
		{name: "Boolean exact passes", filter: map[string]string{"cuda_enabled": "true"}, expected: true},
		{name: "Boolean mismatch fails", filter: map[string]string{"cuda_enabled": "false"}, expected: false},
		{name: "Math less-than passes", filter: map[string]string{"rtt_ms": "<1500"}, expected: true},
		{name: "Math greater-than-equal passes", filter: map[string]string{"vram_gb": ">=16"}, expected: true},
		{name: "Missing key fails", filter: map[string]string{"gpu_temp": "<80"}, expected: false},
		{name: "Math condition fails", filter: map[string]string{"vram_gb": ">32"}, expected: false},
		{name: "Invalid numeric filter fails", filter: map[string]string{"vram_gb": ">=abc"}, expected: false},
		{name: "Combined filters pass", filter: map[string]string{"model": "llama-3", "vram_gb": ">=16", "rtt_ms": "<1500"}, expected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EvaluateOptions(tc.filter, workerOptions)
			if result != tc.expected {
				t.Errorf("Expected %v but got %v for filter %v", tc.expected, result, tc.filter)
			}
		})
	}
}
