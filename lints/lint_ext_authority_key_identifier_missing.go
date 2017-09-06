// lint_ext_authority_key_identifier_missing.go
/***********************************************************************
RFC 5280: 4.2.1.1
The keyIdentifier field of the authorityKeyIdentifier extension MUST
   be included in all certificates generated by conforming CAs to
   facilitate certification path construction.  There is one exception;
   where a CA distributes its public key in the form of a "self-signed"
   certificate, the authority key identifier MAY be omitted.  The
   signature on a self-signed certificate is generated with the private
   key associated with the certificate's subject public key.  (This
   proves that the issuer possesses both the public and private keys.)
   In this case, the subject and authority key identifiers would be
   identical, but only the subject key identifier is needed for
   certification path building.
***********************************************************************/

package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type authorityKeyIdMissing struct{}

func (l *authorityKeyIdMissing) Initialize() error {
	return nil
}

func (l *authorityKeyIdMissing) CheckApplies(c *x509.Certificate) bool {
	return !util.IsRootCA(c)
}

func (l *authorityKeyIdMissing) Execute(c *x509.Certificate) *LintResult {
	if !util.IsExtInCert(c, util.AuthkeyOID) && !util.IsSelfSigned(c) {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_authority_key_identifier_missing",
		Description:   "CAs must support key identifiers and include them in all certificates",
		Citation:      "RFC 5280: 4.2 & 4.2.1.1",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &authorityKeyIdMissing{},
	})
}
