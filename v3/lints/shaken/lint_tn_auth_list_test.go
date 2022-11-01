package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_tnAuthList_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_tn_auth_list")
}

func Test_tnAuthList_Execute(t *testing.T) {
	test.Execute(t, "e_sti_tn_auth_list", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenCertEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall contain TNAuthorizationList extension",
			},
		},
		{
			Name: "TNAuthList has multiple TN entries",
			File: "shakenTNAuthMultiple.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "TNAuthorizationList shall have only one TN Entry",
			},
		},
		{
			Name: "TNAuthList has zero-length TN entry",
			File: "shakenTNAuthEmptyString.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "TN Entry shall contain a SPC value",
			},
		},
		{
			Name: "TNAuthList without TN entry",
			File: "shakenTNAuthEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "TNAuthorizationList shall have only one TN Entry",
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
