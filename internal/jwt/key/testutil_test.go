package key

import (
	"crypto/rand"
	"io"
)

func testRand() io.Reader {
	return rand.Reader
}
