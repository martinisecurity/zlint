package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caCertificatePolicyCritical_CheckApplies(t *testing.T) {
	test.CheckApplies(t, "n_sti_ca_certificate_policy_critical", []test.CheckAppliesVector{
		{
			Name: "Leaf certificate",
			File: "shakenCert.pem",
			Want: false,
		},
		{
			Name: "Intermediate certificate with CP ext",
			File: "shakenCa.pem",
			Want: true,
		},
		{
			Name: "Intermediate certificate without CP ext",
			File: "shakenCaCertPolicyNo.pem",
			Want: false,
		},
		{
			Name: "Root certificate",
			File: "shakenRoot.pem",
			Want: false,
		},
	})
}

func Test_caCertificatePolicyCritical_Execute(t *testing.T) {
	test.Execute(t, "n_sti_ca_certificate_policy_critical", []test.Vector{
		{
			Name: "extension is uncritical",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "extension is critical",
			File: "shakenCaCertPolicyCritical.pem",
			Want: &lint.LintResult{
				Status:  lint.Notice,
				Details: "STI certificates should contain a CertificatePolicies extension marked uncritical",
			},
		},
	})
}
