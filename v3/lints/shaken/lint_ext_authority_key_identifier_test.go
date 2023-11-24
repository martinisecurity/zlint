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

func Test_ExtAuthorityKeyIdentifier(t *testing.T) {
	authKeyId := []byte{0x2b, 0x0e, 0x35, 0x59, 0x9b, 0x9e, 0x1d, 0x9d, 0x8e, 0x3e, 0x0e, 0x2c, 0x9f, 0x2b, 0x0e, 0x35, 0x59, 0x9b, 0x9e, 0x1d, 0x9d, 0x8e, 0x3e, 0x0e}
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
			name: "e_atis_ext_authority_key_identifier leaf",
			args: args{
				lintName: "e_atis_ext_authority_key_identifier",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.AuthkeyOID.String(): {},
					},
					AuthorityKeyId: authKeyId,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_authority_key_identifier leaf without auth key id",
			args: args{
				lintName: "e_atis_ext_authority_key_identifier",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificates shall contain an Authority Key Identifier extension",
			},
		},
		{
			name: "e_atis_ext_authority_key_identifier_ca intermediate",
			args: args{
				lintName: "e_atis_ext_authority_key_identifier_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.AuthkeyOID.String(): {},
					},
					AuthorityKeyId: authKeyId,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_authority_key_identifier_ca root",
			args: args{
				lintName: "e_atis_ext_authority_key_identifier_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Date,
					IsCA:       true,
					SelfSigned: true,
					ExtensionsMap: map[string]pkix.Extension{
						util.AuthkeyOID.String(): {},
					},
					AuthorityKeyId: authKeyId,
				},
				config: lint.NewEmptyConfig(),
			},
			// Root certificates use the e_atis_ext_authority_key_identifier_root lint
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
