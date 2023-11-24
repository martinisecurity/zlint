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

func Test_ExtBasicConstraints(t *testing.T) {
	basicConstraintsLeafRaw := []byte{0x30, 0x00}
	basicConstraintsCAFalseRaw := []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}

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
			name: "e_atis_ext_basic_constraints leaf",
			args: args{
				lintName: "e_atis_ext_basic_constraints",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.BasicConstOID.String(): {
							Critical: true,
							Value:    basicConstraintsLeafRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_basic_constraints ca",
			args: args{
				lintName: "e_atis_ext_basic_constraints",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.BasicConstOID.String(): {
							Critical: true,
							Value:    basicConstraintsCAFalseRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_basic_constraints missing",
			args: args{
				lintName: "e_atis_ext_basic_constraints",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "BasicConstraints extension not found",
			},
		},
		{
			name: "e_atis_ext_basic_constraints not critical",
			args: args{
				lintName: "e_atis_ext_basic_constraints",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.BasicConstOID.String(): {
							Critical: false,
							Value:    basicConstraintsCAFalseRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "BasicConstraints extension is not marked critical",
			},
		},
		{
			name: "e_atis_ext_basic_constraints wrong structure",
			args: args{
				lintName: "e_atis_ext_basic_constraints",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.BasicConstOID.String(): {
							Critical: true,
							Value:    []byte{0x02, 0x01, 0x00},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Failed to parse BasicConstraints extension",
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
