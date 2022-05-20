package tls

import (
	"fmt"
	"strings"
)

// BreakIntoNextProtos takes in a prefix and a value and breaks it into a
// chunks. It is the caller's responsibility to ensure that prefix and value are
// something real.
func BreakIntoNextProtos(prefix, value string) []string {
	var count int
	maxSize := 240 - len(prefix)
	ret := make([]string, 0, len(value)/maxSize+1)
	for i := 0; i < len(value); i += maxSize {
		end := i + maxSize
		if end > len(value) {
			end = len(value)
		}
		ret = append(ret, fmt.Sprintf("%s%02d-%s", prefix, count, value[i:end]))
		count++
	}
	return ret
}

// CombineFromNextProtos takes in a prefix and chunks and combines it from
// chunks. It is the caller's responsibility to ensure that the contained chunks
// are in sequence and relevant and sanity check the result.
func CombineFromNextProtos(prefix string, chunks []string) string {
	var ret string
	for _, chunk := range chunks {
		// Strip that and the number
		if strings.HasPrefix(chunk, prefix) {
			ret += strings.TrimPrefix(chunk, prefix)[3:]
		}
	}
	return ret
}
