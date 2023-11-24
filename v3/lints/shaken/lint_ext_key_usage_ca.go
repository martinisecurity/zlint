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

type keyUsageCa struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_atis_ext_key_usage_ca",
			Description:   "The Key Usage extension for STI root and intermediate certificates shall contain a single key usage value of keyCertSign (5) and may contain the key usage values digitalSignature (0) and/or cRLSign (6).",
			Citation:      ATIS1000080v003_STI_Citation,
			Source:        lint.ATIS1000080,
			EffectiveDate: util.ATIS1000080_v003_Date,
		},
		Lint: NewKeyUsageCa,
	})
}

func NewKeyUsageCa() lint.LintInterface {
	return &keyUsageCa{}
}

// CheckApplies implements lint.LintInterface
func (*keyUsageCa) CheckApplies(c *x509.Certificate) bool {
	return c.IsCA && util.IsExtInCert(c, util.KeyUsageOID)
}

// Execute implements lint.LintInterface
func (*keyUsageCa) Execute(c *x509.Certificate) *lint.LintResult {
	keyUsage := c.KeyUsage

	if IsSTIv1_4(c) {
		if keyUsage != x509.KeyUsageCertSign {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain a single key usage value of keyCertSign (5).",
			}
		}
	} else {
		flags := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if keyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign &&
			(keyUsage|flags)^flags == 0 {
			return &lint.LintResult{
				Status: lint.Pass,
			}
		}

		return &lint.LintResult{
			Status:  lint.Error,
			Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
		}
	}

	return &lint.LintResult{
		Status: lint.Pass,
	}
}
