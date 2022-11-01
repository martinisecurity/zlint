package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSignatureAlgorithm_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_atis_ca_signature_algorithm")
}

func Test_caSignatureAlgorithm_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_signature_algorithm", []test.Vector{
		{
			Name: "incorrect algorithm",
			File: "shakenCaSigAlgSHA1.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Signature Algorithm field with the value 'ecdsa-with-SHA256'",
			},
		},
		{
			Name: "correct algorithm",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
