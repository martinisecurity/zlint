package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caIssuerDn_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_sti_ca_issuer_dn")
}

func Test_caIssuerDn_Execute(t *testing.T) {
	test.Execute(t, "e_sti_ca_issuer_dn", []test.Vector{
		{
			Name: "correct DN",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "CN is missed",
			File: "shakenCaIssuerWithoutCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "O is missed",
			File: "shakenCaIssuerWithoutO.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "C is missed",
			File: "shakenCaIssuerWithoutC.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
	})
}
