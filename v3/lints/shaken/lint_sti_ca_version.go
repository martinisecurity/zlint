package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type caVersion struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_ca_version",
		Description:   version_details,
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Date,
		Lint:          NewCaVersion,
	})
}

func NewCaVersion() lint.LintInterface {
	return &caVersion{}
}

// CheckApplies implements lint.LintInterface
func (*caVersion) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA
}

// Execute implements lint.LintInterface
func (*caVersion) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertVersion(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
