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

func Test_ExtCrlDistribution(t *testing.T) {
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
			name: "e_atis_ext_crl_distribution leaf",
			args: args{
				lintName: "e_atis_ext_crl_distribution",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
						},
					},
					CRLDistributionPoints: []string{
						"http://crl3.digicert.com/sha2-ev-server-g2.crl",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_crl_distribution leaf empty",
			args: args{
				lintName: "e_atis_ext_crl_distribution",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI End-Entity certificates shall contain a CRL Distribution Points extension",
			},
		},
		{
			name: "e_atis_ext_crl_distribution leaf multiple points",
			args: args{
				lintName: "e_atis_ext_crl_distribution",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
						},
					},
					CRLDistributionPoints: []string{
						"http://crl3.digicert.com/sha2-ev-server-g2.crl",
						"http://crl4.digicert.com/sha2-ev-server-g2.crl",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL Distribution Points extension should contain a single DistributionPoint entry",
			},
		},
		{
			name: "e_atis_ext_crl_distribution leaf zero points",
			args: args{
				lintName: "e_atis_ext_crl_distribution",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
						},
					},
					CRLDistributionPoints: []string{},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL Distribution Points extension should contain a single DistributionPoint entry",
			},
		},
		{
			name: "e_atis_ext_crl_distribution leaf not http",
			args: args{
				lintName: "e_atis_ext_crl_distribution",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
						},
					},
					CRLDistributionPoints: []string{
						"ftp://crl3.digicert.com/sha2-ev-server-g2.crl",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "DistributionPoint filed shall contain the HTTP URL reference to the CRL",
			},
		},
		{
			name: "e_atis_ext_crl_distribution_ca intermediate",
			args: args{
				lintName: "e_atis_ext_crl_distribution_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
						},
					},
					CRLDistributionPoints: []string{
						"http://crl3.digicert.com/sha2-ev-server-g2.crl",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_crl_distribution_ca root",
			args: args{
				lintName: "e_atis_ext_crl_distribution_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
			// The Root CA uses e_atis_ext_crl_distribution_root lint
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
