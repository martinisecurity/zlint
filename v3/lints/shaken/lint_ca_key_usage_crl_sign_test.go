package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caKeyUsageCrlSign_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_us_cp_ca_key_usage_crl_sign")
}

func Test_caKeyUsageCrlSign_Execute(t *testing.T) {
	test.Execute(t, "e_us_cp_ca_key_usage_crl_sign", []test.Vector{
		{
			Name: "without crlSign",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "with crlSign",
			File: "shakenCaKeyUsageWCRL.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The model for managing and communicating the status of revoked certificates is in the form of a distributed Certificate Revocation List (CRL) that is maintained by the STI-PA as described in ATIS-1000080",
			},
		},
	})
}
