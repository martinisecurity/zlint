package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_issuer_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_atis_issuer_dn")
}

func Test_issuer_Execute(t *testing.T) {
	test.Execute(t, "e_atis_issuer_dn", []test.Vector{
		{
			Name: "correct DN",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "CN is missed",
			File: "shakenIssuerWithoutCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "O is missed",
			File: "shakenIssuerWithoutO.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "C is missed",
			File: "shakenIssuerWithoutC.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
	})
}
