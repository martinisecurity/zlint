package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_basicConstraints_CheckApplies(t *testing.T) {
	test.CheckAppliesAllCertificates(t, "e_atis_basic_constraints")
}

func Test_basicConstraints_Execute(t *testing.T) {
	test.Execute(t, "e_atis_basic_constraints", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenBasicConstNo.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a BasicConstraints extension marked critical",
			},
		},
		{
			Name: "extension is not critical",
			File: "shakenBasicConstNotCritical.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain a BasicConstraints extension marked critical",
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
