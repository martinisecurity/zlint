package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type stringList struct {
	Items []string
}

func newStringList(items []string) *stringList {
	return &stringList{
		Items: items,
	}
}

func (t *stringList) Contains(id string) bool {
	for _, v := range t.Items {
		if id == v {
			return true
		}
	}

	return false
}

type extensionUnknown struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_extension_unknown",
		Description:   "STI certificate shall not include extensions that are not specified",
		Citation:      "Citation",
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewExtensionUnknown,
	})
}

func NewExtensionUnknown() lint.LintInterface {
	return &extensionUnknown{}
}

// CheckApplies implements lint.LintInterface
func (*extensionUnknown) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*extensionUnknown) Execute(c *x509.Certificate) *lint.LintResult {
	var shakenExtensions = newStringList([]string{
		"2.5.29.14",          // subject key identifier
		"2.5.29.35",          // authority key identifier
		"2.5.29.19",          // basicConstraints
		"2.5.29.15",          // keyUsage
		"1.3.6.1.5.5.7.1.26", // tnAuthList
		"2.5.29.31",          // cRLDistributionPoints
		"2.5.29.32",          // certificatePolicies
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
