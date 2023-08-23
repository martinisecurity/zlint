package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_cp_1_1_key_size_Execute(t *testing.T) {
	test.Execute(t, "e_cp_1_1_key_size", []test.Vector{
		{
			Name: "incorrect algorithm",
			File: "shakenSigAlgSHA1.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall use the ECDSA with SHA-256 algorithm when generating digital signatures",
			},
		},
		{
			Name: "certificate with CP v1.1",
			File: "shakenCP1_1Cert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "certificate with CP v1.2",
			File: "shakenCP1_2Cert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "certificate with CP v1.3",
			File: "shakenCP1_3Cert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "certificate with CP v1.4",
			File: "shakenCP1_4Cert.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
	})
}

func Test_cp_1_4_key_size_Execute(t *testing.T) {
	test.Execute(t, "e_cp_1_4_key_size", []test.Vector{
		{
			Name: "certificate with CP v1.1",
			File: "shakenCP1_1Cert.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			Name: "certificate with CP v1.2",
			File: "shakenCP1_2Cert.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			Name: "certificate with CP v1.3",
			File: "shakenCP1_3Cert.pem",
			Want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			Name: "certificate signed with ECDSA and SHA-256",
			File: "shakenCP1_4Cert.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "certificate signed with ECDSA and SHA-384",
			File: "shakenCP1_4WSHA384.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "certificate signed with ECDSA and SHA-1",
			File: "shakenCP1_4WSHA1.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall use the ECDSA with SHA-256 or ECDSA with SHA-384 algorithm when generating digital signatures",
			},
		},
	})
}
