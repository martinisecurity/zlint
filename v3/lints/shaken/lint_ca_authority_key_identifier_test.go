package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caAuthorityKeyIdentifier_CheckApplies(t *testing.T) {
	test.CheckAppliesIntermediateCertificate(t, "e_sti_ca_authority_key_identifier")
}

func Test_caAuthorityKeyIdentifier_Execute(t *testing.T) {
	test.Execute(t, "e_sti_ca_authority_key_identifier", []test.Vector{
		{
			Name: "extension is correct",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "extension is absent",
			File: "shakenCaEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain an Authority Key Identifier extension",
			},
		},
	})
}
