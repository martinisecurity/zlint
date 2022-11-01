package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caVersion_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_sti_ca_version")
}

func Test_caVersion_Execute(t *testing.T) {
	test.Execute(t, "e_sti_ca_version", []test.Vector{
		{
			Name: "incorrect certificate Version",
			File: "shakenCaVersion2.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain Version field specifying version 3",
			},
		},
		{
			Name: "correct certificate Version",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
