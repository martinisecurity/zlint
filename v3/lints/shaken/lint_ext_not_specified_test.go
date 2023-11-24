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

func Test_ExtNotSpecified(t *testing.T) {
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
			name: "e_atis_ext_not_specified leaf",
			args: args{
				lintName: "e_atis_ext_not_specified",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Extensions: []pkix.Extension{
						{
							Id:       util.KeyUsageOID,
							Critical: true,
						},
						{
							Id:       util.BasicConstOID,
							Critical: true,
						},
						{
							Id: util.CertPolicyOID,
						},
						{
							Id: util.SubjectKeyIdentityOID,
						},
						{
							Id: util.AuthkeyOID,
						},
						{
							Id: util.CrlDistOID,
						},
						{
							Id: util.TNAuthListOID,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_not_specified leaf odd extension",
			args: args{
				lintName: "e_atis_ext_not_specified",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Extensions: []pkix.Extension{
						{
							Id:       util.KeyUsageOID,
							Critical: true,
						},
						{
							Id:       util.BasicConstOID,
							Critical: true,
						},
						{
							Id: util.CertPolicyOID,
						},
						{
							Id: util.SubjectKeyIdentityOID,
						},
						{
							Id: util.AuthkeyOID,
						},
						{
							Id: util.CrlDistOID,
						},
						{
							Id: util.TNAuthListOID,
						},
						{
							Id: util.SubjectAlternateNameOID,
						},
						{
							Id: util.IssuerAlternateNameOID,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Certificate contains extensions that are not specified: 2.5.29.17, 2.5.29.18",
			},
		},
		{
			name: "e_atis_ext_not_specified_ca intermediate",
			args: args{
				lintName: "e_atis_ext_not_specified_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: false,
					Extensions: []pkix.Extension{
						{
							Id:       util.KeyUsageOID,
							Critical: true,
						},
						{
							Id:       util.BasicConstOID,
							Critical: true,
						},
						{
							Id: util.CertPolicyOID,
						},
						{
							Id: util.SubjectKeyIdentityOID,
						},
						{
							Id: util.AuthkeyOID,
						},
						{
							Id: util.CrlDistOID,
						},
						{
							Id: util.TNAuthListOID,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_not_specified_ca root",
			args: args{
				lintName: "e_atis_ext_not_specified_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Date,
					IsCA:       true,
					SelfSigned: true,
					Extensions: []pkix.Extension{
						{
							Id:       util.KeyUsageOID,
							Critical: true,
						},
						{
							Id:       util.BasicConstOID,
							Critical: true,
						},
						{
							Id: util.CertPolicyOID,
						},
						{
							Id: util.SubjectKeyIdentityOID,
						},
						{
							Id: util.AuthkeyOID,
						},
						{
							Id: util.CrlDistOID,
						},
						{
							Id: util.TNAuthListOID,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
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
