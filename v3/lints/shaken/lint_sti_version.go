package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type version struct{}

var version_details = "STI certificates shall contain Version field specifying version 3"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_sti_version",
		Description:   version_details,
		Citation:      ATIS1000080_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v004_Leaf_Date,
		Lint:          NewVersion,
	})
}

func NewVersion() lint.LintInterface {
	return &version{}
}

// CheckApplies implements lint.LintInterface
func (*version) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*version) Execute(c *x509.Certificate) *lint.LintResult {
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

func assertVersion(c *x509.Certificate) error {
	if c.Version != 3 {
		return fmt.Errorf(version_details)
	}

	return nil
}
