package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
CP 1.3: 3.1 Naming
	The `serialNumber` attribute shall be included along with the CN (to form a terminal relative
	distinguished name set), to distinguish among successive instances of certificates associated
	with the same entity.
************************************************/

type subjectSnShall struct {
	ca bool
}

func init() {
	description := "The DN shall contain a serialNumber attribute."
	lint.RegisterLint(&lint.Lint{
		Name:          "e_us_cp_subject_sn_shall",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
		Lint:          NewSubjectSnShallLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_us_cp_subject_sn_shall_ca",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Date,
		Lint:          NewSubjectSnShallCA,
	})
}

func NewSubjectSnShall(ca bool) lint.LintInterface {
	return &subjectSnShall{ca}
}

func NewSubjectSnShallLeaf() lint.LintInterface {
	return &subjectSnShall{false}
}

func NewSubjectSnShallCA() lint.LintInterface {
	return &subjectSnShall{true}
}

// CheckApplies implements lint.LintInterface
func (l *subjectSnShall) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && IsSTIv1_3(c)
}

// Execute implements lint.LintInterface
func (l *subjectSnShall) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.SerialNumber == "" {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The DN does not contain a serialNumber attribute.",
		}
	}
	if c.Subject.SerialNumber != c.SerialNumber.String() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The DN serialNumber attribute does not match the certificate serialNumber.",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
