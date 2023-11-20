package shaken

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestParseTNAuthorizationList(t *testing.T) {
	res, err := ParseTNAuthorizationList([]byte{48, 8, 160, 6, 22, 4, 55, 48, 57, 74})
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(res)
}

func TestParseCRLDistributionPoints(t *testing.T) {
	raw1, err := hex.DecodeString("30819F30819CA03EA03C863A68747470733A2F2F61757468656E7469636174652D6170692D7374672E69636F6E65637469762E636F6D2F646F776E6C6F61642F76312F63726CA25AA4583056311430120603550407130B4272696467657761746572310B3009060355040813024E4A311330110603550403130A5354492D50412043524C310B3009060355040613025553310F300D060355040A13065354492D5041")
	if err != nil {
		t.Fatal(err.Error())
	}

	type args struct {
		raw []byte
	}
	tests := []struct {
		name    string
		args    args
		want    func(res CRLDistributionPoints) error
		wantErr bool
	}{
		{
			name: "Correctly parses CRLDistributionPoints",
			args: args{
				raw: raw1,
			},
			want: func(res CRLDistributionPoints) error {
				if len(res) != 1 {
					return fmt.Errorf("CRLDistributionPoints should have 1 DistributionPoint")
				}
				if len(res[0].DistributionPointName.Bytes) == 0 {
					return fmt.Errorf("CRLDistributionPoints should have a DistributionPoint")
				}
				if len(res[0].CRLIssuer.Bytes) == 0 {
					return fmt.Errorf("CRLDistributionPoints should have a CRLIssuer")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCRLDistributionPoints(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCRLDistributionPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err := tt.want(got); err != nil {
				t.Errorf("ParseCRLDistributionPoints() = %v, want %v", got, err)
			}
		})
	}
}
