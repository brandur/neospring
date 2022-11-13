package main

import (
	_ "embed"
	"strings"

	"github.com/brandur/neospring/internal/util/randutil"
)

var quotes []string

//go:embed test_content.md
var quotesRaw string

func init() {
	quotes = parseQuotes(quotesRaw)
}

func getRandomQuote() string {
	return quotes[randutil.Intn(int64(len(quotes)-1))]
}

func parseQuotes(raw string) []string {
	quotes := strings.Split(raw, "---")

	formattedQuotes := make([]string, 0, len(quotes))

	for _, quote := range quotes {
		quote = strings.TrimSpace(quote)

		if quote == "" {
			continue
		}

		quote = strings.ReplaceAll(quote, "\n\n", "</p><p>")
		quote = strings.ReplaceAll(quote, "\n", " ")
		quote = strings.ReplaceAll(quote, "</p><p>", "</p>\n\n<p>")
		quote = "<p>" + quote + "</p>"
		formattedQuotes = append(formattedQuotes, quote)
	}

	return formattedQuotes
}
