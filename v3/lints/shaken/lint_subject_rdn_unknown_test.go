package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectRdnUnknown_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "w_pki_subject_rdn_unknown")
}

func Test_subjectRdnUnknown_Execute(t *testing.T) {
	test.Execute(t, "w_pki_subject_rdn_unknown", []test.Vector{
		{
			Name: "RDN is correct", // CN, C, O, SERIALNUMBER
			File: "shakenSubject.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "odd name", // CN, C, O, SERIALNUMBER , E
			File: "shakenSubjectWEmail.pem",
			Want: &lint.LintResult{
				Status:  lint.Warn,
				Details: "Only CN, C, O, L, and SERIALNUMBER should be included. Additional RNDs may introduce ambiguity and may not be verifiable",
			},
		},
	})
}
