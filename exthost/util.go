/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package exthost

import (
	"strconv"
)

func ToUInt64(val interface{}) uint64 {
	switch val := val.(type) {
	case int:
		return uint64(val)
	case int32:
		return uint64(val)
	case int64:
		return uint64(val)
	case uint64:
		return val
	case float32:
		return uint64(val)
	case float64:
		return uint64(val)
	case string:
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0
		}
		return uint64(i)
	default:
		return 0
	}
}

func ToUInt(val interface{}) uint {
	switch val := val.(type) {
	case int:
		return uint(val)
	case int32:
		return uint(val)
	case int64:
		return uint(val)
	case float32:
		return uint(val)
	case float64:
		return uint(val)
	case string:
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0
		}
		return uint(i)
	default:
		return 0
	}
}

// contains checks if a string is present in a slice
func contains(s []string, str string) bool {
  for _, v := range s {
    if v == str {
      return true
    }
  }
  return false
}
