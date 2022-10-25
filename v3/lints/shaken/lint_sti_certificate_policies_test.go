package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_certificatePolicies_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_certificate_policies")
}

func Test_certificatePolicies_Execute(t *testing.T) {
	test.Execute(t, "e_sti_certificate_policies", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenCertPolicyNo.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a Certificate Policies extension containing a single SHAKEN Certificate Policy",
			},
		},
		{
			Name: "SHAKEN policy is absent",
			File: "shakenCertPolicyIncorrect.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall contain '2.16.840.1.114569.1.1.3' policy",
			},
		},
		{
			Name: "SHAKEN policy is not single",
			File: "shakenCertPolicyMultiple.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a Certificate Policies extension containing a single SHAKEN Certificate Policy",
			},
		},
		{
			Name: "SHAKEN policy is correct",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
