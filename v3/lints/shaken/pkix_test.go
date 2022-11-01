package shaken

import (
	"fmt"
	"testing"
)

func TestParseTNAuthorizationList(t *testing.T) {
	res, err := ParseTNAuthorizationList([]byte{48, 8, 160, 6, 22, 4, 55, 48, 57, 74})
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(res)
}
