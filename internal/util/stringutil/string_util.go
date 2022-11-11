package stringutil

import "fmt"

// SampleLong samples a long string by taking some content from the beginning
// and some from the end. Useful when you want to show a part of something like
// a response body which might be very long, or when reflecting user input into
// logs or back in a response body in case they sent something degenerately
// long.
func SampleLong(s string) string {
	if len(s) <= 100 {
		return s
	}

	return fmt.Sprintf("%s ... [TRUNCATED; total_length: %v characters] ... %s", s[0:50], len(s), s[len(s)-50:len(s)-1])
}
