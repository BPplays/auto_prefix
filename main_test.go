package main

import (
	"fmt"
	// "log"
	// "net/netip"
	"testing"
	// "time"

	// "github.com/BPplays/auto_prefix/source"
)


func TestSprintTime(t *testing.T) {


	t.Run("testSprintTimeks", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Source: "url", Url: "https://localhost:38081/json/go/prefix"}
		npf, err := get_prefix(cfg, true)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(npf)



	})

}

