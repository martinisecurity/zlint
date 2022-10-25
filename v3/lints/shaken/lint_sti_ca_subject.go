package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caSubject struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_subject",
		Description:   subject_details,
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaSubject,
	})
}

func NewCaSubject() lint.LintInterface {
	return &caSubject{}
}

// CheckApplies implements lint.LintInterface
func (*caSubject) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caSubject) Execute(c *x509.Certificate) *lint.LintResult {
	missedAttrs := make([]string, 0)

	// check names
	if len(c.Subject.CommonNames) == 0 {
		missedAttrs = append(missedAttrs, "Common Name")
	}
	if len(c.Subject.Country) == 0 {
		missedAttrs = append(missedAttrs, "Country")
	}
	if len(c.Subject.Organization) == 0 {
		missedAttrs = append(missedAttrs, "Organization")
	}

	if len(missedAttrs) != 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The DN shall contain a Country (C=) attribute, a Common Name (CN=) attribute and an Organization (O=) attribute",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
