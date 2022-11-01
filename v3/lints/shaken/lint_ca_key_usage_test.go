package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caKeyUsage_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_atis_ca_key_usage")
}

func Test_caKeyUsage_Execute(t *testing.T) {
	test.Execute(t, "e_atis_ca_key_usage", []test.Vector{
		{
			Name: "KeyUsage with keyCertSign flag",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "KeyUsage with keyCertSign, crlSign flags",
			File: "shakenCaKeyUsageWCRL.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "KeyUsage with keyCertSign, crlSign, digitalSignature flags",
			File: "shakenCaKeyUsageCertSignCRLSignDigSign.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "KeyUsage with keyCertSign, digitalSignature flags",
			File: "shakenCaKeyUsageCertSignDigSign.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "KeyUsage without keyCertSign flags",
			File: "shakenCaKeyUsageWithoutCertSign.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
			},
		},
		{
			Name: "KeyUsage with odd flag",
			File: "shakenCaKeyUsageOddFlag.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
			},
		},
	})
}
