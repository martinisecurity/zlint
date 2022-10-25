package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_pkiCaKeyUsage_CheckApplies(t *testing.T) {
	test.CheckApplies(t, "n_pki_ca_key_usage", []test.CheckAppliesVector{
		{
			Name: "Leaf certificate",
			File: "aiaCrit.pem",
			Want: false,
		},
		{
			Name: "CA with ext",
			File: "caKeyUsageNoCRL.pem",
			Want: true,
		},
		{
			Name: "CA without ext",
			File: "caKeyUsageMissing.pem",
			Want: false,
		},
	})
}

func Test_pkiCaKeyUsage_Execute(t *testing.T) {
	test.Execute(t, "n_pki_ca_key_usage", []test.Vector{
		{
			Name: "keyCertSign flag only",
			File: "caKeyUsageNoCRL.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "without keyCertSign flag",
			File: "caKeyUsageNoCertSign.pem",
			Want: &lint.LintResult{
				Status:  lint.Notice,
				Details: "For CA certificates, the Key Usage extension should contain a single key usage value of keyCertSign",
			},
		},
		{
			Name: "without keyCertSign and odd flag",
			File: "shakenCaKeyUsageCertSignDigSign.pem",
			Want: &lint.LintResult{
				Status:  lint.Notice,
				Details: "For CA certificates, the Key Usage extension should contain a single key usage value of keyCertSign",
			},
		},
	})
}
