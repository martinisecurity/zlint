package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN intermediate and end entity certificates shall include a Certificate Policies Extension
	containing a single OID value that identifies the SHAKEN Certificate Policy established by the
	STI-PA. The OID value is specified in the SHAKEN Certificate Policy document.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI intermediate and End-Entity certificates shall include a Certificate Policies extension
	containing a single OID value that identifies the SHAKEN Certificate Policy established by the
	STI-PA. The OID value is specified in the SHAKEN Certificate Policy document.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI intermediate and end-entity certificates shall include a Certificate Policies extension
	containing a single OID value that identifies the SHAKEN Certificate Policy established by the
	STI-PA. The OID value is specified in the SHAKEN Certificate Policy document. STI root certificates
	shall not contain a Certificate Policies extension.
************************************************/

type certificatePolicies struct {
	ca bool
}

func init() {
	description := "STI intermediate and end-entity certificates shall include a Certificate Policies extension containing a single OID value that identifies the SHAKEN Certificate Policy established by the STI-PA."
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_certificate_policies",
			Description:   description,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		},
		Lint: NewCertificatePoliciesLeaf,
	})

	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_certificate_policies_ca",
			Description:   description,
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewCertificatePoliciesCA,
	})
}

func NewCertificatePolicies(ca bool) lint.LintInterface {
	return &certificatePolicies{ca}
}

func NewCertificatePoliciesLeaf() lint.LintInterface {
	return NewCertificatePolicies(false)
}

func NewCertificatePoliciesCA() lint.LintInterface {
	return NewCertificatePolicies(true)
}

// CheckApplies implements lint.LintInterface
func (l *certificatePolicies) CheckApplies(c *x509.Certificate) bool {
	return l.ca == c.IsCA && !util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (*certificatePolicies) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.CertPolicyOID)
	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Certificate Policies extension is not present",
		}
	}

	if ext.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Certificate Policies extension is marked as critical",
		}
	}

	cps := c.PolicyIdentifiers

	if len(cps) != 1 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Certificate Policies extension does not contain a single OID value",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
