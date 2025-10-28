package main

import (
	"fmt"
	"net/netip"
	// "log"
	// "net/netip"
	"testing"
	// "time"
	// "github.com/BPplays/auto_prefix/source"
)

// func TestSprintTime(t *testing.T) {
//
//
// 	t.Run("testSprintTimeks", func(t *testing.T) {
// 		t.Parallel()
//
// 		cfg := Config{Source: "url", Url: "https://localhost:38081/json/go/prefix"}
// 		npf, err := get_prefix(cfg, true)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		fmt.Println(npf)
//
//
//
// 	})
//
// }


func TestMixPrefixIP(t *testing.T) {


	t.Run("test prefix ip mix", func(t *testing.T) {
		t.Parallel()

		pref := netip.MustParsePrefix("2001:db8:ffff:ffff::/64")
		suffix := netip.MustParseAddr("::aaaa:aaaa:aaaa:aaaa")
		mixed := mixPrefixIP(&pref, &suffix)
		preMixed := netip.MustParsePrefix("2001:db8:ffff:ffff:aaaa:aaaa:aaaa:aaaa/64")
		if (*mixed) != preMixed {
			t.Error("premixed is diff\n")
		}



	})

	t.Run("test prefix ip mix", func(t *testing.T) {
		t.Parallel()

		pref := netip.MustParsePrefix("2001:db8:ffff:ffff::/65")
		suffix := netip.MustParseAddr("::ffaa:aaaa:aaaa:aaaa")
		mixed := mixPrefixIP(&pref, &suffix)
		fmt.Println(mixed)
		preMixed := netip.MustParsePrefix("2001:db8:ffff:ffff:7faa:aaaa:aaaa:aaaa/65")
		if (*mixed) != preMixed {
			t.Error("premixed is diff\n")
		}



	})

}


func TestLooseParseSuffix(t *testing.T) {


	t.Run("test prefix ip mix", func(t *testing.T) {
		t.Parallel()

		ip, err := looseParseSuffix("cafe:babe")
		if err != nil {
			t.Error("should parse with no errors\n")
		}

		if ip.String() != "::cafe:babe" {
			t.Error("looseParseSuffix failed to parse ip\n")
		}



	})

	t.Run("test prefix ip mix", func(t *testing.T) {
		t.Parallel()


		ip, err := looseParseSuffix(":cafe:babe")
		if err != nil {
			t.Error("should parse with no errors\n")
		}

		if ip.String() != "::cafe:babe" {
			t.Error("looseParseSuffix failed to parse ip\n")
		}



	})

}
