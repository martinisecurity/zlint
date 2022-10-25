package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subject_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_subject")
}

func Test_subject_Execute(t *testing.T) {
	test.Execute(t, "e_sti_subject", []test.Vector{
		{
			Name: "CN is missed",
			File: "shakenSubjectWithoutCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "O is missed",
			File: "shakenSubjectWithoutO.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "C is missed",
			File: "shakenSubjectWithoutC.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
			},
		},
		{
			Name: "correct subject DN",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
