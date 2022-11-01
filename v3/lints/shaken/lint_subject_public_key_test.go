package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectPublicKey_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_atis_subject_public_key")
}

func Test_subjectPublicKey_Execute(t *testing.T) {
	test.Execute(t, "e_atis_subject_public_key", []test.Vector{
		{
			Name: "incorrect named curve",
			File: "shakenKeyAlgP384.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key",
			},
		},
		{
			Name: "incorrect key algorithm",
			File: "shakenKeyAlgRSA.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key",
			},
		},
		{
			Name: "correct key algorithm",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
