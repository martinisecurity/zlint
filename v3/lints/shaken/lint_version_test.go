package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_version_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_atis_version")
}

func Test_version_Execute(t *testing.T) {
	test.Execute(t, "e_atis_version", []test.Vector{
		{
			Name: "incorrect certificate version",
			File: "shakenCertV2.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain Version field specifying version 3",
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
