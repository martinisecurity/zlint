package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
CP 1.4: 3.1 Naming
	Issuer and subject DNs, shall include single country name (C) which shall be "US" for all certificates produced under this policy.
************************************************/

type subjectCUs struct {
	ca bool
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_c_us",
		Description:   "Subject MUST contain a Country (C=) of \"US\".",
		Citation:      United_States_SHAKEN_CPv1_4_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
		Lint:          NewSubjectCUsLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_c_us_ca",
		Description:   "Subject MUST contain a Country (C=) of \"US\".",
		Citation:      "ATIS-1000080",
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_4_Date,
		Lint:          NewSubjectCUsCA,
	})
}

func NewSubjectCUs(ca bool) lint.LintInterface {
	return &subjectCUs{ca}
}

func NewSubjectCUsLeaf() lint.LintInterface {
	return NewSubjectCUs(false)
}

func NewSubjectCUsCA() lint.LintInterface {
	return NewSubjectCUs(true)
}

// CheckApplies implements lint.LintInterface
func (l *subjectCUs) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && IsSTIv1_4(c)
}

// Execute implements lint.LintInterface
func (l *subjectCUs) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.Country == nil || len(c.Subject.Country) != 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject MUST be present and MUST contain exactly one value for Country (C=).",
		}
	}
	countyCode := c.Subject.Country[0]
	if countyCode != "US" {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Subject MUST contain a Country (C=) of \"US\".",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
