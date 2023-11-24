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

func Test_SubjectCnSpc(t *testing.T) {
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
			name: "e_atis_subject_cn_spc correct 1",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN 709J",
					},
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
			name: "e_atis_subject_cn_spc without TNAuthList",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN 709J",
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Cannot get SPC value from the TNAuthList extension, STI certificate shall contain TNAuthorizationList extension",
			},
		},
		{
			name: "e_atis_subject_cn_spc another SPC",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN 1234",
					},
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
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common name shall contain the text string 'SHAKEN 709J', but common name is 'SHAKEN 1234'",
			},
		},
		{
			name: "e_atis_subject_cn_spc SPC with extra characters",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN 709J1",
					},
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
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common name shall contain the text string 'SHAKEN 709J', but common name is 'SHAKEN 709J1'",
			},
		},
		{
			name: "e_atis_subject_cn_spc SHAKEN with extra characters",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "sSHAKEN 709J",
					},
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
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common name shall contain the text string 'SHAKEN 709J', but common name is 'sSHAKEN 709J'",
			},
		},
		{
			name: "e_atis_subject_cn_spc SHAKEN with extra space",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					Subject: pkix.Name{
						CommonName: "SHAKEN  709J",
					},
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
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "Common name shall contain the text string 'SHAKEN 709J', but common name is 'SHAKEN  709J'",
			},
		},
		{
			name: "e_atis_subject_cn_spc intermediate",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       true,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			name: "e_atis_subject_cn_spc root",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       true,
					SelfSigned: true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.NA,
			},
		},
		{
			name: "e_atis_subject_cn_spc ATIS v003",
			args: args{
				lintName: "e_atis_subject_cn_spc",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v003_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status: lint.NE,
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
