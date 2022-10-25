package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_crlDistribution_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_crl_distribution")
}

func Test_crlDistribution_Execute(t *testing.T) {
	test.Execute(t, "e_sti_crl_distribution", []test.Vector{
		{
			Name: "extension is absent",
			File: "shakenCertEmpty.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI End-Entity certificates shall contain a CRL Distribution Points extension",
			},
		},
		{
			Name: "CRL is multiple",
			File: "shakenCRLPointMultiple.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL Distribution Points extension should contain a single DistributionPoint entry",
			},
		},
		{
			Name: "CRL is not reachable",
			File: "shakenCRLPointUnreachable.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL Distribution Point shall be reachable if the requesting IP address within the program ACLs",
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
