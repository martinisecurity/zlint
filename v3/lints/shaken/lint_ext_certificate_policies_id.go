package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
CP 1.3: 1.3 Document Name and Identification
	This policy has been assigned the following Object Identifier [OID]:
	2.16.840.1.114569.1.1.3 for SHAKEN CP Version 1.3

CP 1.4: 1.2 Document Name and Identification
	This policy has been assigned the following Object Identifier [OID]:
	2.16.840.1.114569.1.1.4 for SHAKEN CP Version 1.4.
************************************************/

type certificatePoliciesId struct {
	ca bool
}

func init() {
	description := "The Certificate Policies extension MUST contain a single OID value that identifies the SHAKEN Certificate Policy established by the STI-PA"
	lint.RegisterLint(&lint.Lint{
		Name:          "e_shaken_certificate_policies_id",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_1_3,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
		Lint:          NewCertificatePoliciesIdLeaf,
	})
	lint.RegisterLint(&lint.Lint{
		Name:          "e_shaken_certificate_policies_id_ca",
		Description:   description,
		Citation:      United_States_SHAKEN_CPv1_3_Citation_1_3,
		Source:        lint.UnitedStatesSHAKENCP,
		EffectiveDate: util.UnitedStatesSHAKENCPv1_3_Date,
		Lint:          NewCertificatePoliciesIdCA,
	})
}

func NewCertificatePoliciesId(ca bool) lint.LintInterface {
	return &certificatePoliciesId{ca}
}

func NewCertificatePoliciesIdLeaf() lint.LintInterface {
	return NewCertificatePoliciesId(false)
}

func NewCertificatePoliciesIdCA() lint.LintInterface {
	return NewCertificatePoliciesId(true)
}

// CheckApplies implements lint.LintInterface
func (l *certificatePoliciesId) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && !util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (l *certificatePoliciesId) Execute(c *x509.Certificate) *lint.LintResult {
	cps := c.PolicyIdentifiers

	if len(cps) != 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "the Certificate Policies extension does not contain a single OID value that identifies the SHAKEN Certificate Policy established by the STI-PA",
		}
	}

	wellknownPolicies := []string{
		util.ShakenUnitedStatesCPv1_3OID.String(),
		util.ShakenUnitedStatesCPv1_4OID.String(),
	}

	// check wellknown policies contain the policy identifier
	found := false
	for _, policy := range wellknownPolicies {
		if policy == cps[0].String() {
			found = true
			break
		}
	}

	if !found {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("the Certificate Policies extension contains an invalid OID value: %s. Available OIDs: %v", cps[0].String(), wellknownPolicies),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
