package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectCN_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_subject_cn")
}

func Test_subjectCN_Execute(t *testing.T) {
	test.Execute(t, "e_sti_subject_cn", []test.Vector{
		{
			Name: "incorrect subject CN",
			File: "shakenCertEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Cannot get SPC value from the TNAuthList extension, STI certificate shall contain TNAuthorizationList extension",
			},
		},
		{
			Name: "incorrect SPC value",
			File: "shakenSubjectCN.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common name shall contain the text string 'SHAKEN 6629'",
			},
		},
		{
			Name: "correct subject CN",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
