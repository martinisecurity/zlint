package shaken

import (
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
CP 1.3: 3.1 Naming
	Names used in the STI certificates shall represent an unambiguous identifier for the SP Subject.

CP 1.4: 3.1 Naming
	Names used in the STI Certificates shall represent an unambiguous identifier for the SP Subject.
************************************************/

const subjectRdn_details = "Names used in the STI certificates shall represent an unambiguous identifier for the SP Subject."

type subjectRdnUnknown struct {
	ca bool
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_shaken_subject_rdn_unknown",
		Description:   subjectRdn_details,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
		Lint:          NewSubjectRdnUnknownLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_shaken_subject_rdn_unknown_ca",
		Description:   subjectRdn_details,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_3_1,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Date,
		Lint:          NewSubjectRdnUnknownCA,
	})
}

func NewSubjectRdnUnknown(ca bool) lint.LintInterface {
	return &subjectRdnUnknown{ca}
}

func NewSubjectRdnUnknownLeaf() lint.LintInterface {
	return &subjectRdnUnknown{false}
}

func NewSubjectRdnUnknownCA() lint.LintInterface {
	return &subjectRdnUnknown{true}
}

// CheckApplies implements lint.LintInterface
func (l *subjectRdnUnknown) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && (IsSTIv1_3(c) || IsSTIv1_4(c))
}

// Execute implements lint.LintInterface
func (*subjectRdnUnknown) Execute(c *x509.Certificate) *lint.LintResult {
	list := []string{
		"2.5.4.3",              // commonName from ATIS
		"2.5.4.6",              // countryName from ATIS
		"2.5.4.10",             // organization from ATIS
		"2.5.4.5",              // SERIALNUMBER from CP
		"1.2.840.113549.1.9.1", // email from PKI
		"2.5.4.8",              // state from PKI
	}
	unknownNames := []string{}
	for _, name := range c.Subject.Names {
		if !contains(list, name.Type.String()) {
			unknownNames = append(unknownNames, name.Type.String())
		}
	}

	if len(unknownNames) > 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("The DN contains unknown RDNs: %s", strings.Join(unknownNames, ", ")),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
