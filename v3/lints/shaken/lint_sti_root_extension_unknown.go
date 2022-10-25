package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type rootExtensionUnknown struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_root_extension_unknown",
		Description:   "STI certificate shall not include extensions that are not specified",
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewRootExtensionUnknown,
	})
}

func NewRootExtensionUnknown() lint.LintInterface {
	return &rootExtensionUnknown{}
}

// CheckApplies implements lint.LintInterface
func (*rootExtensionUnknown) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && c.SelfSigned
}

// Execute implements lint.LintInterface
func (*rootExtensionUnknown) Execute(c *x509.Certificate) *lint.LintResult {
	var shakenExtensions = newStringList([]string{
		"2.5.29.14", // subject key identifier
		"2.5.29.35", // authority key identifier
		"2.5.29.19", // basicConstraints
		"2.5.29.15", // keyUsage
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
