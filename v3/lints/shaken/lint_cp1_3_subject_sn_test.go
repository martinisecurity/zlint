package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_subjectSN_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_cp1_3_subject_sn")
}

func Test_subjectSN_Execute(t *testing.T) {
	test.Execute(t, "e_cp1_3_subject_sn", []test.Vector{
		{
			Name: "SERIALNUMBER is absent",
			File: "shakenSubjectWithoutSerialNumber.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a ‘serialNumber’ attribute along with the CN",
			},
		},
		{
			Name: "multiple SERIALNUMBER",
			File: "shakenSubjectWSerialNumberMultiple.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a ‘serialNumber’ attribute along with the CN",
			},
		},
		{
			Name: "SERIALNUMBER presents",
			File: "shakenSubject.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
