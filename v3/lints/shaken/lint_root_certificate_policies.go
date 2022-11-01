package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type rootCertificatePolicies struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_root_certificate_policies",
		Description:   "STI Root certificates shall not contain a Certificate Policies extension",
		Citation:      ATIS1000080v004_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewRootCertificatePolicies,
	})
}

func NewRootCertificatePolicies() lint.LintInterface {
	return &rootCertificatePolicies{}
}

// CheckApplies implements lint.LintInterface
func (*rootCertificatePolicies) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && c.SelfSigned
}

// Execute implements lint.LintInterface
func (*rootCertificatePolicies) Execute(c *x509.Certificate) *lint.LintResult {
	if ext := util.GetExtFromCert(c, util.CertPolicyOID); ext != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "STI Root certificates shall not contain a Certificate Policy extension",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
