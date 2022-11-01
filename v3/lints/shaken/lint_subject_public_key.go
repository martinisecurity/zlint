package shaken

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subjectPublicKey struct{}

const subjectPublicKey_details = "STI certificates shall contain a Subject Public Key Info field specifying a Public Key Algorithm of \"id-ecPublicKey\" and containing a 256-bit public key"

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_atis_subject_public_key",
		Description:   subjectPublicKey_details,
		Citation:      ATIS1000080v003_STI_Citation,
		Source:        lint.ATIS1000080,
		EffectiveDate: util.ATIS1000080_v003_Leaf_Date,
		Lint:          NewSubjectPublicKey,
	})
}

func NewSubjectPublicKey() lint.LintInterface {
	return &subjectPublicKey{}
}

// CheckApplies implements lint.LintInterface
func (*subjectPublicKey) CheckApplies(c *x509.Certificate) bool {
	return !c.IsCA
}

// Execute implements lint.LintInterface
func (*subjectPublicKey) Execute(c *x509.Certificate) *lint.LintResult {
	if err := assertSubjectPublicKey(c); err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}

func assertSubjectPublicKey(c *x509.Certificate) error {
	if c.PublicKeyAlgorithmOID.String() != "1.2.840.10045.2.1" {
		return fmt.Errorf(subjectPublicKey_details)
	}

	ecKey := c.PublicKey.(*x509.AugmentedECDSA)
	if ecKey == nil || ecKey.Pub.Curve.Params().Name != "P-256" {
		return fmt.Errorf(subjectPublicKey_details)
	}

	return nil
}
