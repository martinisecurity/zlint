package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type keyUsage struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_key_usage",
		Description:   "STI certificates shall contain a Key Usage extension marked as critical. For End-Entity certificates, the Key Usage extension shall contain a single key usage value of digitalSignature (0).",
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewKeyUsage,
	})
}

func NewKeyUsage() lint.LintInterface {
	return &keyUsage{}
}

// CheckApplies implements lint.LintInterface
func (*keyUsage) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*keyUsage) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.KeyUsageOID)
	if ext != nil && ext.Critical {
		if c.KeyUsage == x509.KeyUsageDigitalSignature {
			return &lint.LintResult{
				Status: lint.Pass,
			}
		}

		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Key Usage extension shall contain a single key usage value of digitalSignature",
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI certificates shall contain a Key Usage extension marked as critical",
	}
}
