package shaken

/************************************************
ATIS-1000080v005: 6.4.1.1 STI Certificate Fields
	STI certificates shall not include extensions that are not specified.
************************************************/

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type extNotSpecified struct {
	ca bool
}

var allowedExtensions = map[string]bool{
	util.KeyUsageOID.String():           true,
	util.BasicConstOID.String():         true,
	util.CertPolicyOID.String():         true,
	util.SubjectKeyIdentityOID.String(): true,
	util.AuthkeyOID.String():            true,
	util.CrlDistOID.String():            true,
	util.TNAuthListOID.String():         true,
}

func init() {
	description := "STI certificates shall not include extensions that are not specified."

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_not_specified",
		Description:   description,
		Citation:      ATIS1000080v005_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v005_Leaf_Date,
		Lint:          NewExtNotSpecifiedLeaf,
	})

	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_not_specified_ca",
		Description:   description,
		Citation:      ATIS1000080v005_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v005_Date,
		Lint:          NewExtNotSpecifiedCA,
	})
}

func NewExtNotSpecified(ca bool) lint.LintInterface {
	return &extNotSpecified{ca}
}

func NewExtNotSpecifiedLeaf() lint.LintInterface {
	return NewExtNotSpecified(false)
}

func NewExtNotSpecifiedCA() lint.LintInterface {
	return NewExtNotSpecified(true)
}

// CheckApplies implements LintInterface.
func (l *extNotSpecified) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA
}

// Execute implements LintInterface.
func (l *extNotSpecified) Execute(c *x509.Certificate) *lint.LintResult {
	oddExtensions := []string{}
	for _, ext := range c.Extensions {
		extnID := ext.Id.String()
		if !allowedExtensions[extnID] {
			oddExtensions = append(oddExtensions, extnID)
		}
	}

	if len(oddExtensions) > 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Certificate contains extensions that are not specified: %s", strings.Join(oddExtensions, ", ")),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
