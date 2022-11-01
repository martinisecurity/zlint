package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectEmail_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "w_cp_1_3_subject_email")
}

func Test_subjectEmail_Execute(t *testing.T) {
	test.Execute(t, "w_cp_1_3_subject_email", []test.Vector{
		{
			Name: "name without Email",
			File: "shakenSubject.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "name with Email",
			File: "shakenSubjectWEmail.pem",
			Want: &lint.LintResult{
				Status:  lint.Warn,
				Details: "Email addresses are not allowed as the CP does not specify how to validate them",
			},
		},
	})
}
