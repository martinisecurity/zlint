package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_authorityKeyIdentifier_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_atis_authority_key_identifier")
}

func Test_authorityKeyIdentifier_Execute(t *testing.T) {
	test.Execute(t, "e_atis_authority_key_identifier", []test.Vector{
		{
			Name: "AKI extension is absent",
			File: "shakenSubject.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain an Authority Key Identifier extension",
			},
		},
		{
			Name: "AKI extension exists",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
