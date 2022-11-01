package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_crlCaDistribution_CheckApplies(t *testing.T) {
	test.CheckAppliesIntermediateCertificate(t, "e_atis_ca_crl_distribution")
}

func Test_crlCaDistribution_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_crl_distribution", []test.Vector{
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
				Details: "STI Intermediate certificates shall contain a CRL Distribution Points extension",
			},
		},
	})
}
