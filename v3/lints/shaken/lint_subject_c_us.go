package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
)

/************************************************
CP 1.4: 3.1 Naming
	Issuer and subject DNs, shall include single country name (C) which shall be "US" for all certificates produced under this policy.
************************************************/

type subjectCUs struct {
	ca bool
}

func init() {
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
