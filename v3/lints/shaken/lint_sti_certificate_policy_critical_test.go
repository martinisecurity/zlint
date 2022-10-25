package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_certificatePolicyCritical_CheckApplies(t *testing.T) {
	test.CheckApplies(t, "n_sti_certificate_policy_critical", []test.CheckAppliesVector{
		{
			Name: "Leaf certificate with CP ext",
			File: "shakenCert.pem",
			Want: true,
		},
		{
			Name: "Leaf certificate without CP ext",
			File: "shakenCertPolicyNo.pem",
			Want: false,
		},
		{
			Name: "Intermediate certificate",
			File: "caBasicConstCrit.pem",
			Want: false,
		},
		{
			Name: "Root certificate",
			File: "rootCAValid.pem",
			Want: false,
		},
	})
}

func Test_certificatePolicyCritical_Execute(t *testing.T) {
	test.Execute(t, "n_sti_certificate_policy_critical", []test.Vector{
		{
			Name: "CertificatePolicies extension is critical",
			File: "shakenCertPolicyCritical.pem",
			Want: &lint.LintResult{
				Status:  lint.Notice,
				Details: "STI certificates should contain a CertificatePolicies extension marked uncritical",
			},
		},
		{
			Name: "CertificatePolicies extension is uncritical",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
