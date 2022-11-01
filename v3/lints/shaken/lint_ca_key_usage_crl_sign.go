package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caKeyUsageCrlSign struct{}

const caKeyUsageCrlSign_details = "The model for managing and communicating the status of revoked certificates is in the form of a distributed Certificate Revocation List (CRL) that is maintained by the STI-PA as described in ATIS-1000080"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_us_cp_ca_key_usage_crl_sign",
		Description:   caKeyUsageCrlSign_details,
		Citation:      United_States_SHAKEN_CPv1_1_Citation_4_9,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_1_Date,
		Lint:          NewCaKeyUsageCrlSign,
	})
}

func NewCaKeyUsageCrlSign() lint.LintInterface {
	return &caKeyUsageCrlSign{}
}

// CheckApplies implements lint.LintInterface
func (*caKeyUsageCrlSign) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caKeyUsageCrlSign) Execute(c *x509.Certificate) *lint.LintResult {
	if c.KeyUsage&x509.KeyUsageCRLSign == x509.KeyUsageCRLSign {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: caKeyUsageCrlSign_details,
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
