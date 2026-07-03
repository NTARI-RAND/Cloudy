package coord

import "testing"

func TestDialConstructs(t *testing.T) {
	c := Dial("http://localhost:8080")
	if c == nil || c.Coordinator == nil {
		t.Fatal("Dial returned an unwired client")
	}
}
