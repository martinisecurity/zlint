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

func Test_ExtTnAuthList(t *testing.T) {
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
			name: "e_atis_tn_auth_list",
			args: args{
				lintName: "e_atis_tn_auth_list",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
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
			name: "e_atis_tn_auth_list not found",
			args: args{
				lintName: "e_atis_tn_auth_list",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "the TNAuthList extension is not present",
			},
		},
		{
			name: "e_atis_tn_auth_list critical",
			args: args{
				lintName: "e_atis_tn_auth_list",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.TNAuthListOID.String(): {
							Id:       util.TNAuthListOID,
							Critical: true,
							Value:    tnAuthListRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "the TNAuthList extension is marked as critical",
			},
		},
		{
			name: "e_atis_tn_auth_list intermediate",
			args: args{
				lintName: "e_atis_tn_auth_list",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
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
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_atis_tn_auth_list root",
			args: args{
				lintName: "e_atis_tn_auth_list",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
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
