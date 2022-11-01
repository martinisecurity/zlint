package shaken_test

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func Test_rootExtensionUnknown_CheckApplies(t *testing.T) {
	test.CheckAppliesRootCertificate(t, "e_atis_root_extension_unknown")
}

func Test_rootExtensionUnknown_Execute(t *testing.T) {
	test.Execute(t, "e_atis_root_extension_unknown", []test.Vector{
		{
			Name: "list of allowed extension",
			File: "shakenRoot.pem",
			Want: &lint.LintResult{
				Status: lint.Pass,
			},
		},
		{
			Name: "list with odd ext",
			File: "shakenRootExtOdd.pem",
			Want: &lint.LintResult{
				Status:  lint.Error,
				Details: "STI certificate shall not include extensions that are not specified",
			},
		},
	})
}
