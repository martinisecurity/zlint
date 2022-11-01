package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_keyUsage_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_key_usage")
}

func Test_keyUsage_Execute(t *testing.T) {
	test.Execute(t, "e_sti_key_usage", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenCertEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Key Usage extension marked as critical",
			},
		},
		{
			Name: "keyUsage is uncritical",
			File: "shakenKeyUsageNotCritical.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Key Usage extension marked as critical",
			},
		},
		{
			Name: "keyUsage odd flags",
			File: "shakenKeyUsageOdd.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain a single key usage value of digitalSignature",
			},
		},
		{
			Name: "extension is correct",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
