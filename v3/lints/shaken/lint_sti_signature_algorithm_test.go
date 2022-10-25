package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_signatureAlgorithm_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_signature_algorithm")
}

func Test_signatureAlgorithm_Execute(t *testing.T) {
	test.Execute(t, "e_sti_signature_algorithm", []test.Vector{
		{
			Name: "incorrect algorithm",
			File: "shakenSigAlgSHA1.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Signature Algorithm field with the value 'ecdsa-with-SHA256'",
			},
		},
		{
			Name: "correct certificate version",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
