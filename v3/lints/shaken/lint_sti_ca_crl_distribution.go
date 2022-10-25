package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caCrlDistribution struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_crl_distribution",
		Description:   "STI intermediate certificates shall contain a CRL Distribution Points extension containing a single DistributionPoint entry",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaCrlDistribution,
	})
}

func NewCaCrlDistribution() lint.LintInterface {
	return &caCrlDistribution{}
}

// CheckApplies implements lint.LintInterface
func (*caCrlDistribution) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && !c.SelfSigned
}

// Execute implements lint.LintInterface
func (*caCrlDistribution) Execute(c *x509.Certificate) *lint.LintResult {
	if ext := util.GetExtFromCert(c, util.CrlDistOID); ext != nil {
		if err := assertCrlDistributionPoint(c); err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: err.Error(),
			}
		}

		return &lint.LintResult{
			Status: lint.Pass,
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI Intermediate certificates shall contain a CRL Distribution Points extension",
	}
}
