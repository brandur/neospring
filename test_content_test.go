package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseQuotes(t *testing.T) {
	require.Equal(t, []string{
		`<p>"You mean old books?"</p>

<p>"Stories written before space travel but about space travel."</p>

<p>"How could there have been stories about space travel before —"</p>

<p>"The writers," Pris said, "made it up."</p>`,
		`<p>Strange how paranoia can link up with reality now and then.</p>`,
		`<p>Reality is that which, when you stop believing in it, doesn't go away.</p>`,
	},
		parseQuotes(`"You mean old books?"

"Stories written before space travel but about space travel."

"How could there have been stories about space travel before —"

"The writers," Pris said, "made it up."

---

Strange how paranoia can link up with reality now and then.

---

Reality is that which, when you stop believing in it, doesn't go away.

---`))
}
