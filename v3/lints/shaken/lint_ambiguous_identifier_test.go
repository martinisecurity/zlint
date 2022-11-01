package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_ambiguousIdentifiers_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_cp1_3_ambiguous_identifier")
}

func Test_ambiguousIdentifiers_Execute(t *testing.T) {
	test.Execute(t, "e_cp1_3_ambiguous_identifier", []test.Vector{
		{
			Name: "CN is empty",
			File: "subjectEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall contain TNAuthorizationList extension",
			},
		},
		{
			Name: "CN is ambiguous", // CN=Some SHAKEN 123J
			File: "shakenSubjectAmbiguous.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Names used in the STI certificates shall represent an unambiguous identifier for the SP Subject",
			},
		},
		{
			Name: "correct CN",
			File: "shakenSubject.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
