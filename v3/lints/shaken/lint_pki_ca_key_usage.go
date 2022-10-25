package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type pkiCaKeyUsage struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_pki_ca_key_usage",
		Description:   "For CA certificates, the Key Usage extension should contain a single key usage value of keyCertSign",
		Citation:      PKI_Citation,
		Source:        lint.ShakenPKI,
		EffectiveDate: util.ZeroDate,
		Lint:          NewPkiCaKeyUsage,
	})
}

func NewPkiCaKeyUsage() lint.LintInterface {
	return &pkiCaKeyUsage{}
}

// CheckApplies implements lint.LintInterface
func (*pkiCaKeyUsage) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && util.GetExtFromCert(c, util.KeyUsageOID) != nil
}

// Execute implements lint.LintInterface
func (*pkiCaKeyUsage) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage != x509.KeyUsageCertSign {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "For CA certificates, the Key Usage extension should contain a single key usage value of keyCertSign",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
