package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caExtensionUnknown struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ca_extension_unknown",
		Description:   "STI certificate shall not include extensions that are not specified",
		Citation:      ATIS1000080v004_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaExtensionUnknown,
	})
}

func NewCaExtensionUnknown() lint.LintInterface {
	return &caExtensionUnknown{}
}

// CheckApplies implements lint.LintInterface
func (*caExtensionUnknown) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && !c.SelfSigned
}

// Execute implements lint.LintInterface
func (*caExtensionUnknown) Execute(c *x509.Certificate) *lint.LintResult {
	var shakenExtensions = newStringList([]string{
		"2.5.29.14", // subject key identifier
		"2.5.29.35", // authority key identifier
		"2.5.29.19", // basicConstraints
		"2.5.29.15", // keyUsage
		"2.5.29.31", // cRLDistributionPoints
		"2.5.29.32", // certificatePolicies
	})
	for _, extension := range c.Extensions {
		if !shakenExtensions.Contains(extension.Id.String()) {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall not include extensions that are not specified",
			}
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
