package core

import (
	"fmt"
	"strconv"
	"strings"
)

// AnyOptionsMatch returns true if at least one entry in options passes EvaluateOptions.
// An empty options slice with a non-empty filter returns false.
func AnyOptionsMatch(filter map[string]string, options []map[string]interface{}) bool {
	if len(filter) == 0 {
		return true
	}
	for _, opt := range options {
		if EvaluateOptions(filter, opt) {
			return true
		}
	}
	return false
}

// FindMatchingOption returns the first options entry that passes EvaluateOptions,
// or nil if none match (or filter is empty).
func FindMatchingOption(filter map[string]string, options []map[string]interface{}) map[string]interface{} {
	for _, opt := range options {
		if EvaluateOptions(filter, opt) {
			return opt
		}
	}
	return nil
}

// EvaluateOptions checks whether all filter constraints pass against worker options.
func EvaluateOptions(filter map[string]string, options map[string]interface{}) bool {
	if len(filter) == 0 {
		return true
	}

	for key, filterVal := range filter {
		workerVal, ok := options[key]
		if !ok {
			return false
		}

		filterVal = strings.TrimSpace(filterVal)
		if filterVal == "" {
			return false
		}

		switch {
		case strings.HasPrefix(filterVal, ">="):
			if !evaluateMath(filterVal[2:], workerVal, ">=") {
				return false
			}
		case strings.HasPrefix(filterVal, "<="):
			if !evaluateMath(filterVal[2:], workerVal, "<=") {
				return false
			}
		case strings.HasPrefix(filterVal, ">"):
			if !evaluateMath(filterVal[1:], workerVal, ">") {
				return false
			}
		case strings.HasPrefix(filterVal, "<"):
			if !evaluateMath(filterVal[1:], workerVal, "<") {
				return false
			}
		default:
			workerStr := strings.TrimSpace(fmt.Sprintf("%v", workerVal))
			if !strings.EqualFold(filterVal, workerStr) {
				return false
			}
		}
	}

	return true
}

func evaluateMath(expectedStr string, workerVal interface{}, operator string) bool {
	expectedFloat, err := strconv.ParseFloat(strings.TrimSpace(expectedStr), 64)
	if err != nil {
		return false
	}

	workerFloat, ok := parseFloat(workerVal)
	if !ok {
		return false
	}

	switch operator {
	case ">=":
		return workerFloat >= expectedFloat
	case "<=":
		return workerFloat <= expectedFloat
	case ">":
		return workerFloat > expectedFloat
	case "<":
		return workerFloat < expectedFloat
	default:
		return false
	}
}

func parseFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}
