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

func Test_ExtSubjectKeyIdentifierSize(t *testing.T) {
	octet20BytesRaw := []byte{4, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	octetByteRaw := []byte{4, 1, 1}

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
			name: "e_atis_subject_key_identifier_size leaf",
			args: args{
				lintName: "e_atis_subject_key_identifier_size",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.SubjectKeyIdentityOID.String(): {
							Value: octet20BytesRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_key_identifier_size leaf not 20 bytes",
			args: args{
				lintName: "e_atis_subject_key_identifier_size",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.SubjectKeyIdentityOID.String(): {
							Value: octetByteRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject Key Identifier extension value is 1 bytes, but must be 20 bytes",
			},
		},
		{
			name: "e_atis_subject_key_identifier_size leaf not found",
			args: args{
				lintName: "e_atis_subject_key_identifier_size",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Subject Key Identifier extension not found",
			},
		},
		{
			name: "e_atis_subject_key_identifier_size_ca intermediate",
			args: args{
				lintName: "e_atis_subject_key_identifier_size_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.SubjectKeyIdentityOID.String(): {
							Value: octet20BytesRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_subject_key_identifier_size_ca root",
			args: args{
				lintName: "e_atis_subject_key_identifier_size_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: true,
					ExtensionsMap: map[string]pkix.Extension{
						util.SubjectKeyIdentityOID.String(): {
							Value: octet20BytesRaw,
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
