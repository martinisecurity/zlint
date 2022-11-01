package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caKeyUsage struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_key_usage",
		Description:   "STI certificates shall contain a Key Usage extension marked as critical. For root and intermediate certificates, the Key Usage extension shall contain the key usage value keyCertSign (5), and may contain the key usage values digitalSignature (0) and/or cRLSign (6)",
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewCaKeyUsage,
	})
}

func NewCaKeyUsage() lint.LintInterface {
	return &caKeyUsage{}
}

// CheckApplies implements lint.LintInterface
func (*caKeyUsage) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caKeyUsage) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.KeyUsageOID)
	if ext != nil && ext.Critical {
		flag := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if c.KeyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign &&
			(c.KeyUsage|flag)^flag == 0 {
			return &lint.LintResult{
				Status: lint.Pass,
			}
		}

		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
		}
	}

	return &lint.LintResult{
		Status:  lint.Error,
		Details: "STI certificates shall contain a Key Usage extension marked as critical",
	}
}
