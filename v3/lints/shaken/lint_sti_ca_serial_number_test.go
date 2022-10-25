package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_caSerialNumber_CheckApplies(t *testing.T) {
	test.CheckAppliesRootOrIntermediateCertificate(t, "e_sti_ca_serial_number")
}

func Test_caSerialNumber_Execute(t *testing.T) {
	test.Execute(t, "e_sti_ca_serial_number", []test.Vector{
		{
			Name: "SN is negative",
			File: "shakenCaSerialNegative.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
			},
		},
		{
			Name: "SN is less than 64-bit",
			File: "shakenCaSerialLess64bit.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
			},
		},
		{
			Name: "SN is correct",
			File: "shakenCa.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
