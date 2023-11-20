package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
  SHAKEN certificates shall contain Version field specifying version 3 (value 2).

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI certificates shall contain Version field specifying version 3 (value 2).

ATIS-1000080v005: 6.4.1.1 STI Certificate Fields
  STI certificates shall contain Version field specifying version 3 (value 2).
************************************************/

type version struct {
	ca bool
}

var version_details = "STI certificates shall contain Version field specifying version 3"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_version",
		Description:   version_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewVersionLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_version_ca",
		Description:   version_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewVersionCA,
	})
}

func NewVersion(ca bool) lint.LintInterface {
	return &version{ca}
}

func NewVersionLeaf() lint.LintInterface {
	return NewVersion(false)
}

func NewVersionCA() lint.LintInterface {
	return NewVersion(true)
}

// CheckApplies implements lint.LintInterface
func (l *version) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA
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
