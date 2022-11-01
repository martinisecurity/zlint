package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSubjectCN_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_sti_ca_subject_cn")
}

func Test_caSubjectCN_Execute(t *testing.T) {
	test.Execute(t, "e_sti_ca_subject_cn", []test.Vector{
		{
			Name: "CN=SHAKEN Intermediate",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "CN=Intermediate",
			File: "shakenCaSubjectCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Common Name attribute shall include the text string \"SHAKEN\"",
			},
		},
	})
}
