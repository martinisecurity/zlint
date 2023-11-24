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

func Test_ExtCrlDistributionRoot(t *testing.T) {
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
			name: "e_atis_ext_crl_distribution_root",
			args: args{
				lintName: "e_atis_ext_crl_distribution_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_crl_distribution_root presents",
			args: args{
				lintName: "e_atis_ext_crl_distribution_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The CRL Distribution Points extension is present in a root certificate",
			},
		},
		{
			name: "e_atis_ext_crl_distribution_root leaf",
			args: args{
				lintName: "e_atis_ext_crl_distribution_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_atis_ext_crl_distribution_root intermediate",
			args: args{
				lintName: "e_atis_ext_crl_distribution_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       true,
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
