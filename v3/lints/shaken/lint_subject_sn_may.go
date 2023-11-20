package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
CP 1.4: 3.1 Naming
	To distinguish among successive instances of certificates associated with the same entity, the
	"serialNumber" naming attribute may also be included in the DN.
************************************************/

type subjectSnMay struct {
	ca bool
}

func init() {
	description := "The DN may contain a serialNumber attribute."
	lint.RegisterLint(&lint.Lint{
		Name:          "e_us_cp_subject_sn_may",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_4_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
		Lint:          NewSubjectSnMayLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_us_cp_subject_sn_may_ca",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_4_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_4_Date,
		Lint:          NewSubjectSnMayCA,
	})
}

func NewSubjectSnMay(ca bool) lint.LintInterface {
	return &subjectSnMay{ca}
}

func NewSubjectSnMayLeaf() lint.LintInterface {
	return &subjectSnMay{false}
}

func NewSubjectSnMayCA() lint.LintInterface {
	return &subjectSnMay{true}
}

// CheckApplies implements lint.LintInterface
func (l *subjectSnMay) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && IsSTIv1_4(c)
}

// Execute implements lint.LintInterface
func (l *subjectSnMay) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.SerialNumber != "" && c.Subject.SerialNumber != c.SerialNumber.String() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The DN serialNumber attribute does not match the certificate serialNumber.",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
