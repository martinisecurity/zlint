package shaken

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_assertCrlDistributionPointStruct(t *testing.T) {
	raw1, err := hex.DecodeString("30819F30819CA03EA03C863A68747470733A2F2F61757468656E7469636174652D6170692D7374672E69636F6E65637469762E636F6D2F646F776E6C6F61642F76312F63726CA25AA4583056311430120603550407130B4272696467657761746572310B3009060355040813024E4A311330110603550403130A5354492D50412043524C310B3009060355040613025553310F300D060355040A13065354492D5041")
	if err != nil {
		t.Fatal(err.Error())
	}
	raw2, err := hex.DecodeString("30333031A02FA02D862B687474703A2F2F63726C2E6964656E74727573742E636F6D2F445354524F4F544341583343524C2E63726C")
	if err != nil {
		t.Fatal(err.Error())
	}

	type args struct {
		raw []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "CRLDistributionPoints correct",
			args: args{
				raw: raw1,
			},
			wantErr: false,
		},
		{
			name: "CRLDistributionPoints without CRLIssuer",
			args: args{
				raw: raw2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := assertCrlDistributionPointStruct(tt.args.raw); (err != nil) != tt.wantErr {
				t.Errorf("assertCrlDistributionPointStruct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ExtCrlDistributionStruct(t *testing.T) {
	crlWithIssuerEnc := "MIGfMIGcoD6gPIY6aHR0cHM6Ly9hdXRoZW50aWNhdGUtYXBpLXN0Zy5pY29uZWN0aXYuY29tL2Rvd25sb2FkL3YxL2NybKJapFgwVjEUMBIGA1UEBwwLQnJpZGdld2F0ZXIxCzAJBgNVBAgMAk5KMRMwEQYDVQQDDApTVEktUEEgQ1JMMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1RJLVBB"
	crlWithIssuerRaw, _ := base64.StdEncoding.DecodeString(crlWithIssuerEnc)
	crlWithoutIssuerEnc := "MEAwPqA8oDqGOGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nvcmdhbml6YXRpb252YWxzaGEyZzIuY3Js"
	crlWithoutIssuerRaw, _ := base64.StdEncoding.DecodeString(crlWithoutIssuerEnc)

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
			name: "e_atis_ext_crl_distribution_struct leaf",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
							Value:    crlWithIssuerRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_crl_distribution_struct missing",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
		},
		{
			name: "e_atis_ext_crl_distribution_struct not asn1",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
							Value:    []byte("not asn1"),
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "failed to unmarshal CRL Distribution Points extension: asn1: syntax error: data truncated",
			},
		},
		{
			name: "e_atis_ext_crl_distribution_struct not sequence",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
							Value:    []byte{0x02, 0x01, 0x00},
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "invalid CRL Distribution Points extension",
			},
		},
		{
			name: "e_atis_ext_crl_distribution_struct_ca intermediate",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
							Value:    crlWithIssuerRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_atis_ext_crl_distribution_struct_ca root",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct_ca",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Date,
					IsCA:       true,
					SelfSigned: true,
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
			// The Root CA uses e_atis_ext_crl_distribution_root lint
		},
		{
			name: "e_atis_ext_crl_distribution_struct without CRLIssuer",
			args: args{
				lintName: "e_atis_ext_crl_distribution_struct",
				cert: &x509.Certificate{
					NotBefore:  util.ATIS1000080_v004_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					ExtensionsMap: map[string]pkix.Extension{
						util.CrlDistOID.String(): {
							Critical: false,
							Value:    crlWithoutIssuerRaw,
						},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL Distribution Point shall contain a CRLIssuer field",
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
