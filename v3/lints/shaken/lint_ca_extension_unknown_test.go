package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caExtensionUnknown_CheckApplies(t *testing.T) {
	test.CheckAppliesIntermediateCertificate(t, "e_atis_ca_extension_unknown")
}

func Test_caExtensionUnknown_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_extension_unknown", []test.Vector{
		{
			Name: "list of allowed extensions",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "list with odd ext",
			File: "shakenCaExtOdd.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall not include extensions that are not specified",
			},
		},
	})
}
