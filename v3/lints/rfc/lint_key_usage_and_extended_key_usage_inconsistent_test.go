package rfc

/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestStrictFail(t *testing.T) {
	inputPath := "kuEkuInconsistent.pem"
	expected := lint.Error
	out := test.TestLint("e_key_usage_and_extended_key_usage_inconsistent", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestStrictPass(t *testing.T) {
	inputPath := "kuEkuConsistent.pem"
	expected := lint.Pass
	out := test.TestLint("e_key_usage_and_extended_key_usage_inconsistent", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestMultiPurposeFail(t *testing.T) {
	inputPath := "kuEkuInconsistentMp.pem"
	expected := lint.Error
	out := test.TestLint("e_key_usage_and_extended_key_usage_inconsistent", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestMultiPurposePass(t *testing.T) {
	inputPath := "kuEkuConsistentMp.pem"
	expected := lint.Pass
	out := test.TestLint("e_key_usage_and_extended_key_usage_inconsistent", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
