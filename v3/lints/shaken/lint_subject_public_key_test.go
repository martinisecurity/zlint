package shaken

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_SubjectPublicKey(t *testing.T) {
	ecdsaP256Enc := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF4oUNxUQc7D0R2WttUYE60g5FZlHg1c855lHaF9vVYg6l3yaGEyVuQbDLoDtGjFDlaX5H/Q1UNGpoaHbfaIbpg=="
	ecdsaP256Raw, _ := base64.StdEncoding.DecodeString(ecdsaP256Enc)
	ecdsaP256, _ := x509.ParsePKIXPublicKey(ecdsaP256Raw)

	ecdsaP384Enc := "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAElsSds0piohatIlbd6FwXZFaBwQId/DjLVzmOWCrDoEphLzvyl89ZblKo5W1nRFdWInv9zISdvGz0MQ9YkYd4xJ8GCj3H6CValgcCJljS/M98+JqrpMoKp3CwCoMKzTiz"
	ecdsaP384Raw, _ := base64.StdEncoding.DecodeString(ecdsaP384Enc)
	ecdsaP384, _ := x509.ParsePKIXPublicKey(ecdsaP384Raw)

	type args struct {
		lintName string
		cert     *x509.Certificate
		config   lint.Configuration
	}

	tests := []struct {
		name string
		args args
		want *lint.LintResult
	}{
		{
			name: "e_atis_subject_public_key correct",
			args: args{
				lintName: "e_atis_subject_public_key",
				cert: &x509.Certificate{
					NotBefore:             util.ATIS1000080_v003_Leaf_Date,
					IsCA:                  false,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
					PublicKey:             ecdsaP256,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_public_key not ecdsa",
			args: args{
				lintName: "e_atis_subject_public_key",
				cert: &x509.Certificate{
					NotBefore:             util.ATIS1000080_v003_Leaf_Date,
					IsCA:                  false,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // rsaEncryption
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject Public Key Info field specifies a Public Key Algorithm of 1.2.840.113549.1.1.1, but must be id-ecPublicKey",
			},
		},
		{
			name: "e_atis_subject_public_key namedCurve P-384",
			// P-384 is allowed for CA certificates only
			args: args{
				lintName: "e_atis_subject_public_key",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  false,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
					PublicKey:             ecdsaP384,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject Public Key Info field contains a public key that is not 256 bits",
			},
		},
		{
			name: "e_atis_subject_public_key_ca namedCurve P-256",
			args: args{
				lintName: "e_atis_subject_public_key_ca",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  true,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
					PublicKey:             ecdsaP256,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			name: "e_atis_subject_public_key_ca namedCurve P-384 without CP v1.4",
			args: args{
				lintName: "e_atis_subject_public_key_ca",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  true,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
					PublicKey:             ecdsaP384,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject Public Key Info field contains a public key that is not 256 bits",
			},
		},
		{
			name: "e_atis_subject_public_key_ca namedCurve P-384 with CP v1.4",
			args: args{
				lintName: "e_atis_subject_public_key_ca",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  true,
					PublicKeyAlgorithmOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
					PublicKey:             ecdsaP384,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Pass,
				Details: "Subject Public Key Info field contains a public key that is 384 bits, which is allowed by CP v1.4",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := test.TestLintCert(tt.args.lintName, tt.args.cert, tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TestLintCert() = %v, want %v", got, tt.want)
			}
		})
	}
}
