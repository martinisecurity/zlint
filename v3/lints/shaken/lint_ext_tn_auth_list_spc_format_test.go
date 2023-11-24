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

func Test_ExtTnAuthListSpcFormat(t *testing.T) {
	tnAuthListRaw := []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x4A}

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
			name: "e_atis_tn_auth_list_spc_format",
			args: args{
				lintName: "e_atis_tn_auth_list_spc_format",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    tnAuthListRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_tn_auth_list_spc_format wrong format",
			args: args{
				lintName: "e_atis_tn_auth_list_spc_format",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: false,
							Value:    []byte{0x30, 0x08, 0xA0, 0x06, 0x16, 0x04, 0x37, 0x30, 0x39, 0x6A},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "the SPC value '709j' contains characters other than uppercase letters and numbers",
			},
		},
		{
			name: "e_atis_tn_auth_list_spc_format intermediate",
			args: args{
				lintName: "e_atis_tn_auth_list_spc_format",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       true,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_atis_tn_auth_list_spc_format intermediate",
			args: args{
				lintName: "e_atis_tn_auth_list_spc_format",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v005_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
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
