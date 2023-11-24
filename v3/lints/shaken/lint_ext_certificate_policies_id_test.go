package shaken

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
	"github.com/zmap/zlint/v3/util"
)

func Test_ExtCertificatePoliciesID(t *testing.T) {
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
			name: "e_shaken_certificate_policies_id leaf CPv1.3",
			args: args{
				lintName: "e_shaken_certificate_policies_id",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_shaken_certificate_policies_id leaf CPv1.4",
			args: args{
				lintName: "e_shaken_certificate_policies_id",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_shaken_certificate_policies_id leaf unknown",
			args: args{
				lintName: "e_shaken_certificate_policies_id",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						{1, 2, 3, 4, 5},
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Certificate Policies extension contains an invalid OID value: 1.2.3.4.5. Available OIDs: 2.16.840.1.114569.1.1.3, 2.16.840.1.114569.1.1.4",
			},
		},
		{
			name: "e_shaken_certificate_policies_id leaf multiple",
			args: args{
				lintName: "e_shaken_certificate_policies_id",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Leaf_Date,
					IsCA:       false,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
						util.ShakenUnitedStatesCPv1_4OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{
				Status:  lint.Error,
				Details: "The Certificate Policies extension does not contain a single OID value that identifies the SHAKEN Certificate Policy established by the STI-PA",
			},
		},
		{
			name: "e_shaken_certificate_policies_id_ca intermediate",
			args: args{
				lintName: "e_shaken_certificate_policies_id_ca",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Date,
					IsCA:       true,
					SelfSigned: false,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.Pass},
		},
		{
			name: "e_shaken_certificate_policies_id_ca root",
			args: args{
				lintName: "e_shaken_certificate_policies_id_ca",
				cert: &x509.Certificate{
					NotBefore:  util.UnitedStatesSHAKENCPv1_3_Date,
					IsCA:       true,
					SelfSigned: true,
					PolicyIdentifiers: []asn1.ObjectIdentifier{
						util.ShakenUnitedStatesCPv1_3OID,
					},
				},
				config: lint.NewEmptyConfig(),
			},
			want: &lint.LintResult{Status: lint.NA},
			// Root certificates use the e_shaken_certificate_policies_root lint
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
