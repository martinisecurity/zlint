package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectKeyIdentifier_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_subject_key_identifier")
}

func Test_subjectKeyIdentifier_Execute(t *testing.T) {
	test.Execute(t, "e_sti_subject_key_identifier", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenCertEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a Subject Key Identifier extension",
			},
		},
		{
			Name: "extension is correct",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
