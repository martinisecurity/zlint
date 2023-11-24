package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_ExtKeyUsageCa(t *testing.T) {
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
			name: "e_atis_ext_key_usage_ca intermediate",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_key_usage_ca with KeyUsageCertSign",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageCertSign,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_key_usage_ca without flags",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: 0,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
			},
		},
		{
			name: "e_atis_ext_key_usage_ca odd flag",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain the key usage value keyCertSign, and may contain the key usage values digitalSignature and/or cRLSign",
			},
		},
		{
			name: "e_atis_ext_key_usage_ca CPv1.4 with KeyUsageCRLSign",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
						util.CertPolicyOID.String(): {
							Critical: false,
						},
					},
					KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension shall contain a single key usage value of keyCertSign (5).",
			},
		},
		{
			name: "e_atis_ext_key_usage_ca CPv1.4 with KeyUsageCertSign",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
						util.CertPolicyOID.String(): {
							Critical: false,
						},
					},
					KeyUsage: x509.KeyUsageCertSign,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			name: "e_atis_ext_key_usage_ca root",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_key_usage_ca leaf",
			args: args{
				lintName: "e_atis_ext_key_usage_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
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
