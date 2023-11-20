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

type certificatePoliciesRoot struct{}

func init() {
	description := "STI root certificates shall not contain a Certificate Policies extension."
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_certificate_policies_root",
		Description:   description,
		Citation:      ATIS1000080v005_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v005_Date,
		Lint:          NewCertificatePoliciesRoot,
	})
}

func NewCertificatePoliciesRoot() lint.LintInterface {
	return &certificatePoliciesRoot{}
}

// CheckApplies implements lint.LintInterface
func (l *certificatePoliciesRoot) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (l *certificatePoliciesRoot) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.CertPolicyOID) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "the Certificate Policies extension is present in a root certificate",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
