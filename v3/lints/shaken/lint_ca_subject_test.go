package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSubject_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_atis_ca_subject")
}

func Test_caSubject_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_subject", []test.Vector{
		{
			Name: "CN is missed",
			File: "shakenCaSubjectWithoutCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "O is missed",
			File: "shakenCaSubjectWithoutO.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "C is missed",
			File: "shakenCaSubjectWithoutC.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "correct subject",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
