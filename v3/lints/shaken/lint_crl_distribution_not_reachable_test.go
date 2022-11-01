package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_crlDistributionNotReachable_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_atis_crl_distribution_not_reachable")
	test.CheckAppliesIntermediateCertificate(t, "e_atis_ca_crl_distribution_not_reachable")
}

func Test_crlDistributionNotReachable_Execute(t *testing.T) {
	test.Execute(t, "e_atis_crl_distribution_not_reachable", []test.Vector{
		{
			Name: "crl is reachable",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "crl is GET reachable",
			File: "shakenCRLPointGet.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Unable to retrieve CRL specified in CRLdp from allow listed IP address",
			},
		},
		{
			Name: "crl is unreachable",
			File: "shakenCRLPointUnreachable.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Unable to retrieve CRL specified in CRLdp from allow listed IP address",
			},
		},
		{
			Name: "crl point is file",
			File: "shakenCRLPointFile.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			Name: "crl point is multiple",
			File: "shakenCRLPointMultiple.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			Name: "no crl ext",
			File: "shakenCRLPointMultiple.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
	})
}
