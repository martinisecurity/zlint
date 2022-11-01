package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSubjectRdnUnknown_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "w_pki_ca_subject_rdn_unknown")
}

func Test_caSubjectRdnUnknown_Execute(t *testing.T) {
	test.Execute(t, "w_pki_ca_subject_rdn_unknown", []test.Vector{
		{
			Name: "RDN is correct", // CN, C, O
			File: "shakenCaSubject.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "odd name", // CN, C, O, E
			File: "shakenCaSubjectWEmail.pem",
			Want: &lint.LintResult{
				Status:  lint.Warn,
				Details: "Only CN, C, L, and O should be included. Additional RNDs may introduce ambiguity and may not be verifiable",
			},
		},
	})
}
