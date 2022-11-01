package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_serialNumber_CheckApplies(t *testing.T) {
	test.CheckAppliesLeafCertificate(t, "e_sti_serial_number")
}

func Test_serialNumber_Execute(t *testing.T) {
	test.Execute(t, "e_sti_serial_number", []test.Vector{
		{
			Name: "SN is negative",
			File: "shakenSerialNumberNegative.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
			},
		},
		{
			Name: "SN is 64-bit with 0 first octet",
			File: "shakenSerialNumberPadded.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
			},
		},
		{
			Name: "SN is less than 64-bit",
			File: "shakenSerialNumberLess64bit.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall include a Serial Number field containing an integer greater than zero. The serial number shall contain at least 64 bits of output from a Cryptographically Secure PseudoRandom Number Generator (CSPRNG)",
			},
		},
		{
			Name: "SN is correct",
			File: "shakenCert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
	})
}
