package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_extensionList_Contains(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_extension_unknown")
}

func Test_extensionUnknown_Execute(t *testing.T) {
	test.Execute(t, "e_sti_extension_unknown", []test.Vector{
		{
			Name: "odd extension",
			File: "shakenExtOdd.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall not include extensions that are not specified",
			},
		},
		{
			Name: "correct extensions",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
