package shaken

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

/************************************************
ATIS-1000080v003: 6.4.1 SHAKEN Certificate Requirements
	SHAKEN certificates shall contain a Key Usage extension marked as critical. For root and
	intermediate certificates, the Key Usage extension shall contain the key usage value
	keyCertSign (5), and may contain the key usage values digitalSignature (0) and/or cRLSign (6).
	For end entity certificates, the Key Usage extension shall contain a single key usage value
	of digitalSignature (0).

ATIS-1000080v004: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a Key Usage extension marked as critical. For root and
	intermediate certificates, the Key Usage extension shall contain the key usage value
	keyCertSign (5), and may contain the key usage values digitalSignature (0) and/or cRLSign (6).
	For End-Entity certificates, the Key Usage extension shall contain a single key usage value
	of digitalSignature (0).

ATIS-1000080v005: 6.4.1 STI Certificate Requirements
	STI certificates shall contain a Key Usage extension marked as critical. For root and intermediate
	certificates, the Key Usage extension shall contain a single key usage value of keyCertSign (5).
	For end-entity certificates, the Key Usage extension shall contain a single key usage value of
	digitalSignature (0).
************************************************/

type keyUsage struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_key_usage",
			Description:   "STI certificates shall contain a Key Usage extension marked as critical.",
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewKeyUsage,
	})
}

func NewKeyUsage() lint.LintInterface {
	return &keyUsage{}
}

// CheckApplies implements lint.LintInterface
func (*keyUsage) CheckApplies(c *x509.Certificate) bool {
	return true
}

// Execute implements lint.LintInterface
func (*keyUsage) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.KeyUsageOID)
	if ext == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Key Usage extension not found",
		}
	}

	if !ext.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Key Usage extension is not marked critical",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
