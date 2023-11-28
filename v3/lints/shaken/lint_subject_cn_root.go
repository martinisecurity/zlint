package shaken

import (
	"fmt"
	"regexp"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
  SHAKEN certificates shall include a Subject field containing a Distinguished Name (DN).
	The DN shall contain a Country (C=) attribute and a Common Name (CN=) attribute. Other
	DN attributes are optional. The DN shall uniquely identify the certificate holder (e.g.,
	by including an Organization (O=) attribute, or by identifying the certificate holder
	in the Common Name attribute). The Common Name attribute shall include the text string
	"SHAKEN" to indicate that this is a SHAKEN certificate. For non-end entity CA certificates
	(Basic Constraints CA boolean = TRUE), the Common Name shall also indicate whether the
	certificate is a root or intermediate certificate. The Common Name of an end entity
	certificate shall include the SPC value identified in the TNAuthList of the certificate
	(e.g., "CN=Comcast SHAKEN cert 1234").

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
  STI certificates shall include a Subject field containing a Distinguished Name (DN),
	which is unique for each subject entity certified under one CA issuer identity, as
	specified in RFC 5280 [Ref 11]. The DN shall contain a Country (C=) attribute, a Common
	Name (CN=) attribute and an Organization (O=) attribute. Other DN attributes are optional.
	For non-End-Entity CA certificates (Basic Constraints CA boolean = TRUE), the Common Name
	attribute shall include the text string "SHAKEN" and also indicate whether the certificate
	is a root or intermediate certificate (e.g., CN=SHAKEN root). The Common Name attribute of
	an End-Entity certificate shall contain the text string `SHAKEN`, followed by a single space,
	followed by the SPC value identified in the TNAuthList of the End-Entity certificate (e.g.,
	"CN=SHAKEN 1234"). The Organization (O=) attribute shall include a legal name of the service
	provider in order to facilitate traceback and operations.

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
  STI certificates shall include a Subject field containing a Distinguished Name (DN), which
	is unique for each subject entity certified under one CA issuer identity, as specified in
	RFC 5280 [Ref 11]. The DN shall contain a Common Name (CN=) attribute, an Organization (O=)
	attribute, and a Country (C=) attribute. The Country (C=) attribute shall contain an ISO 3166-1
	alpha-2 country code [ISO 3166-1, Codes for the Representation of Names of Countries and Their
	Subdivisions]. For root and intermediate certificates, the Common Name attribute shall include
	the text string "SHAKEN". For root certificates, the Common Name attribute shall include the
	text string `ROOT` (case insensitive). The Common Name attribute of an end-entity certificate
	shall contain the text string `SHAKEN`, followed by a single space, followed by the SPC value
	identified in the TNAuthList of the end-entity certificate (e.g., "CN=SHAKEN 1234"). For root
	and intermediate certificates, the Organization (O=) attribute shall include a legal name of
	the STI-CA. For end-entity certificates, the Organization (O=) attribute shall include a legal
	name of the STI Participant. The subject DN of an end-entity certificate is not intended to be
	unique when a new certificate is issued to the same entity for the purpose of replacing an expired
	certificate.
************************************************/

type subjectCnRoot struct{}

func init() {
	description := "For root certificates, the Common Name attribute shall include the text string `ROOT` (case insensitive)."
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_subject_cn_root",
			Description:   description,
			Citation:      ATIS1000080v005_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v005_Date,
		},
		Lint: NewSubjectCnRoot,
	})
}

func NewSubjectCnRoot() lint.LintInterface {
	return &subjectCnRoot{}
}

// CheckApplies implements lint.LintInterface
func (l *subjectCnRoot) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

// Execute implements lint.LintInterface
func (l *subjectCnRoot) Execute(c *x509.Certificate) *lint.LintResult {
	matched, _ := regexp.MatchString(`(?i)\bROOT\b`, c.Subject.CommonName)
	if !matched {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("Common Name attribute '%s' does not include the text string 'ROOT' (case insensitive).", c.Subject.CommonName),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
