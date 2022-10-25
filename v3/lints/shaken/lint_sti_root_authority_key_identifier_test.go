package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestRootAuthorityKeyIdentifier_CheckApplies(t *testing.T) {
	test.CheckApplies(t, "e_sti_root_authority_key_identifier", []test.CheckAppliesVector{
		{
			Name: "Leaf certtificate",
			File: "shakenCert.pem",
			Want: false,
		},
		{
			Name: "Intermediat certtificate",
			File: "shakenCa.pem",
			Want: false,
		},
		{
			Name: "Root certtificate without AKI ext",
			File: "shakenRootNoAKI.pem",
			Want: false,
		},
		{
			Name: "Root certtificate with AKI ext",
			File: "shakenRoot.pem",
			Want: true,
		},
	})
}

func TestRootAuthorityKeyIdentifier_Execute(t *testing.T) {
	test.Execute(t, "e_sti_root_authority_key_identifier", []test.Vector{
		{
			Name: "Root with correct AKI",
			File: "shakenRoot.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "Root with incorrrect SKI ext",
			File: "shakenRootAKIWrong.pem",
			Want: &lint.LintResult{
				Status: lint.Error,
				Details: "Authority Key Identifier shall contain a keyIdentifier field with a value that matches " +
					"the Subject Key Identifier value of the same root certificate",
			},
		},
	})
}
