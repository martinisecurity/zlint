package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSubjectPublicKey_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_atis_ca_subject_public_key")
}

func Test_caSubjectPublicKey_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_subject_public_key", []test.Vector{
		{
			Name: "incorrect algorithm",
			File: "shakenCaKeyAlgRSA.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key",
			},
		},
		{
			Name: "incorrect named curve",
			File: "shakenCaKeyAlgP384.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key",
			},
		},
		{
			Name: "correct certificate",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
