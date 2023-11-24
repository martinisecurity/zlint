package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_ExtKeyUsageEe(t *testing.T) {
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
			name: "e_atis_ext_key_usage_ee",
			args: args{
				lintName: "e_atis_ext_key_usage_ee",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageDigitalSignature,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_key_usage_ee zero flags",
			args: args{
				lintName: "e_atis_ext_key_usage_ee",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
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
				Details: "The Key Usage extension for STI end-entity certificates shall contain a single key usage value of digitalSignature (0).",
			},
		},
		{
			name: "e_atis_ext_key_usage_ee odd flags",
			args: args{
				lintName: "e_atis_ext_key_usage_ee",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
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
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Key Usage extension for STI end-entity certificates shall contain a single key usage value of digitalSignature (0).",
			},
		},
		{
			name: "e_atis_ext_key_usage_ee intermediate",
			args: args{
				lintName: "e_atis_ext_key_usage_ee",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageDigitalSignature,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_atis_ext_key_usage_ee root",
			args: args{
				lintName: "e_atis_ext_key_usage_ee",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
					ExtensionsMap: map[string]pkix.Extension{
						util.KeyUsageOID.String(): {
							Critical: true,
						},
					},
					KeyUsage: x509.KeyUsageDigitalSignature,
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
