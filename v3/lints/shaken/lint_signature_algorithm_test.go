package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_SignatureAlgorithm(t *testing.T) {
	ecdsaP256WithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ecdsaP384WithSHA384 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

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
			name: "e_atis_signature_algorithm leaf with ecdsaP256WithSHA256",
			args: args{
				lintName: "e_atis_signature_algorithm",
				cert: &x509.Certificate{
					NotBefore:             util.ATIS1000080_v003_Leaf_Date,
					IsCA:                  false,
					SelfSigned:            false,
					SignatureAlgorithmOID: ecdsaP256WithSHA256,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_signature_algorithm leaf with ecdsaP384WithSHA384 and CPv1.4",
			args: args{
				lintName: "e_atis_signature_algorithm",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:                  false,
					SelfSigned:            false,
					SignatureAlgorithmOID: ecdsaP384WithSHA384,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Pass,
				Details: "SignatureAlgorithm field is 'ecdsa-with-SHA384' which is allowed by CP v1.4",
			},
		},
		{
			name: "e_atis_signature_algorithm_ca leaf with ecdsaP384WithSHA384 without CPv1.4",
			args: args{
				lintName: "e_atis_signature_algorithm",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Leaf_Date,
					IsCA:                  false,
					SelfSigned:            false,
					SignatureAlgorithmOID: ecdsaP384WithSHA384,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "SignatureAlgorithm field is not 'ecdsa-with-SHA256', got 1.2.840.10045.4.3.3",
			},
		},
		{
			name: "e_atis_signature_algorithm_ca intermediate with ecdsaP256WithSHA256",
			args: args{
				lintName: "e_atis_signature_algorithm_ca",
				cert: &x509.Certificate{
					NotBefore:             util.ATIS1000080_v003_Date,
					IsCA:                  true,
					SelfSigned:            false,
					SignatureAlgorithmOID: ecdsaP256WithSHA256,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_signature_algorithm_ca intermediate with ecdsaP384WithSHA384",
			args: args{
				lintName: "e_atis_signature_algorithm_ca",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  true,
					SelfSigned:            false,
					SignatureAlgorithmOID: ecdsaP384WithSHA384,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Pass,
				Details: "SignatureAlgorithm field is 'ecdsa-with-SHA384' which is allowed by CP v1.4",
			},
		},
		{
			name: "e_atis_signature_algorithm_ca root with ecdsaP256WithSHA256",
			args: args{
				lintName: "e_atis_signature_algorithm_ca",
				cert: &x509.Certificate{
					NotBefore:             util.ATIS1000080_v003_Date,
					IsCA:                  true,
					SelfSigned:            true,
					SignatureAlgorithmOID: ecdsaP256WithSHA256,
					PolicyIdentifiers:     []asn1.ObjectIdentifier{
						// Root certificates do not have CP extension
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			name: "e_atis_signature_algorithm_ca root with ecdsaP384WithSHA384",
			args: args{
				lintName: "e_atis_signature_algorithm_ca",
				cert: &x509.Certificate{
					NotBefore:             util.UnitedStatesSHAKENCPv1_4_Date,
					IsCA:                  true,
					SelfSigned:            true,
					SignatureAlgorithmOID: ecdsaP384WithSHA384,
					PolicyIdentifiers:     []asn1.ObjectIdentifier{
						// Root certificates do not have CP extension
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Pass,
				Details: "SignatureAlgorithm field is 'ecdsa-with-SHA384' which is allowed by CP v1.4",
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
