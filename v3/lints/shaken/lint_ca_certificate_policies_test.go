package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caCertificatePolicies_CheckApplies(t *testing.T) {
	test.CheckAppliesIntermediateCertificate(t, "e_atis_ca_certificate_policies")
}

func Test_caCertificatePolicies_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_certificate_policies", []test.Vector{
		{
			Name: "extension is correct",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "extension is absent",
			File: "shakenCaEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a Certificate Policies extension containing a single SHAKEN Certificate Policy",
			},
		},
		{
			Name: "multiple policies",
			File: "shakenCaCertPolicyMultiple.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall include a Certificate Policies extension containing a single SHAKEN Certificate Policy",
			},
		},
	})
}
