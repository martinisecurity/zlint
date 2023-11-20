package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN end entity certificates shall contain a CRL Distribution Point extension with a
	CRL Distribution Point Name identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA.

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI intermediate and End-Entity certificates shall contain a CRL Distribution Points
	extension containing a single DistributionPoint entry. The DistributionPoint entry shall
	contain a distributionPoint field identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA, and a cRLIssuer field that contains the DN of the
	issuer of the CRL.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI intermediate and end-entity certificates shall contain a CRL Distribution Points
	extension containing a single DistributionPoint entry. The DistributionPoint entry shall
	contain a distributionPoint field identifying the HTTP URL reference to the file containing
	the SHAKEN CRL hosted by the STI-PA, and a CRLIssuer field that matches the DN of the issuer
	of the CRL. STI root certificates shall not contain a CRL Distribution Points extension.
************************************************/

type crlDistributionRoot struct{}

func init() {
	description := "Root certificates shall not contain a CRL Distribution Points extension."
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_ext_crl_distribution_root",
		Description:   description,
		Citation:      ATIS1000080v005_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v005_Date,
		Lint:          NewCrlDistributionRoot,
	})
}

func NewCrlDistributionRoot() lint.LintInterface {
	return &crlDistributionRoot{}
}

// CheckApplies implements lint.LintInterface
func (l *crlDistributionRoot) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (l *crlDistributionRoot) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.CrlDistOID) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "the CRL Distribution Points extension is present in a root certificate",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
