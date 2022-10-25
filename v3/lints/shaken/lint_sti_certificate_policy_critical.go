package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type certificatePolicyCritical struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_sti_certificate_policy_critical",
		Description:   "STI certificates should contain a CertificatePolicies extension marked uncritical",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewCertificatePolicyCritical,
	})
}

func NewCertificatePolicyCritical() lint.LintInterface {
	return &certificatePolicyCritical{}
}

// CheckApplies implements lint.LintInterface
func (*certificatePolicyCritical) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA && util.GetExtFromCert(c, util.CertPolicyOID) != nil
}

// Execute implements lint.LintInterface
func (*certificatePolicyCritical) Execute(c *x509.Certificate) *lint.LintResult {
	certPoliciesExt := util.GetExtFromCert(c, util.CertPolicyOID)
	if certPoliciesExt != nil && certPoliciesExt.Critical {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "STI certificates should contain a CertificatePolicies extension marked uncritical",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
