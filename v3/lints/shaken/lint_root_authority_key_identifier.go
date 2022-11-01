package shaken

import (
	"reflect"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/*
 STI intermediate and End-Entity certificates shall contain an Authority Key Identifier extension (this extension is
 optional for root certificates). For root certificates that contain an Authority Key Identifier extension, the Authority
 Key Identifier shall contain a keyIdentifier field with a value that matches the Subject Key Identifier value of the
 same root certificate. For intermediate and End-Entity certificates, the Authority Key Identifier extension shall
 contain a keyIdentifier field with a value that matches the Subject Key Identifier value of the parent certificate.
*/

type rootAuthorityKeyIdentifier struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name: "e_atis_root_authority_key_identifier",
		Description: "For root certificates that contain an Authority Key Identifier extension, " +
			"the Authority Key Identifier shall contain a keyIdentifier field with a value that matches " +
			"the Subject Key Identifier value of the same root certificate",
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Date,
		Lint:          NewRootAuthorityKeyIdentifier,
	})
}

func NewRootAuthorityKeyIdentifier() lint.LintInterface {
	return &rootAuthorityKeyIdentifier{}
}

// CheckApplies implements lint.LintInterface
func (*rootAuthorityKeyIdentifier) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && c.SelfSigned && len(c.AuthorityKeyId) > 0
}

// Execute implements lint.LintInterface
func (*rootAuthorityKeyIdentifier) Execute(c *x509.Certificate) *lint.LintResult {
	if len(c.SubjectKeyId) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "STI Root certificate shall contain a Subject Key Identifier extension",
		}
	}

	if !reflect.DeepEqual(c.SubjectKeyId, c.AuthorityKeyId) {
		return &lint.LintResult{
			Status: lint.Error,
			Details: "Authority Key Identifier shall contain a keyIdentifier field with a value that matches " +
				"the Subject Key Identifier value of the same root certificate",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
