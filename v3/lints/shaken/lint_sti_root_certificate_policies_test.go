package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestRootCertificatePolicies_CheckApplies(t *testing.T) {
	test.CheckAppliesRootCertificate(t, "e_sti_root_certificate_policies")
}

func TestRootCertificatePolicies_Execute(t *testing.T) {
	test.Execute(t, "e_sti_root_certificate_policies", []test.Vector{
		{
			Name: "root with CP ext",
			File: "shakenRootCertPolicy.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI Root certificates shall not contain a Certificate Policy extension",
			},
		},
		{
			Name: "root without CP ext",
			File: "shakenRoot.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
