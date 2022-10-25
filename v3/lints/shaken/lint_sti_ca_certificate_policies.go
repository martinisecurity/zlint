package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caCertificatePolicies struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_certificate_policies",
		Description:   "STI Intermediate certificates shall include a Certificate Policies extension containing a single OID value that identifies the SHAKEN Certificate Policy established by the STI-PA",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaCertificatePolicies,
	})
}

func NewCaCertificatePolicies() lint.LintInterface {
	return &caCertificatePolicies{}
}

// CheckApplies implements lint.LintInterface
func (*caCertificatePolicies) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && !c.SelfSigned
}

// Execute implements lint.LintInterface
func (*caCertificatePolicies) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.PolicyIdentifiers) == 1 {
		if c.NotBefore.After(util.CPv1_3_Leaf_Date) && !c.PolicyIdentifiers[0].Equal(util.ShakenCPv1_3OID) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall contain '2.16.840.1.114569.1.1.3' policy",
			}
		}

		return &lint.LintResult{
			Status: lint.Pass,
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI certificate shall include a Certificate Policies extension containing a single SHAKEN Certificate Policy",
	}
}
