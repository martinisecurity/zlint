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

func Test_IssuerRoot(t *testing.T) {
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
			name: "e_issuer_root",
			args: args{
				lintName: "e_issuer_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_issuer_root different",
			args: args{
				lintName: "e_issuer_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
					Issuer:     pkix.Name{CommonName: "same"},
					Subject:    pkix.Name{CommonName: "not the same"},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Issuer field of root certificate must match Subject field",
			},
		},
		{
			name: "e_issuer_root intermediate",
			args: args{
				lintName: "e_issuer_root",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_issuer_root leaf",
			args: args{
				lintName: "e_issuer_root",
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
