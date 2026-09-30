package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// passportRule is a well-formed rule encoding the standard thresholds for passports.
const passportRule = "(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type passport) (mrz-verified true))\n"

// writeRules writes a SPOCP rule file to a temp dir and returns the dir path.
// Rules are written in SPOCP advanced format: one rule per line, no quotes.
func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.spoc")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeRules: %v", err)
	}
	return dir
}

// TestNew_EmptyDir verifies that an engine with no rules rejects every scan.
func TestNew_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
	if err := e.EvaluateScan(facetec.ScanResult{}); err == nil {
		t.Fatal("expected rejection with no rules, got nil error")
	}
}

// TestNew_NoDir verifies that an empty rules dir ("") starts with no rules.
func TestNew_NoDir(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatalf("New with empty dir: %v", err)
	}
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
}

// TestNew_NonExistentDir verifies that a missing rules directory returns an error.
func TestNew_NonExistentDir(t *testing.T) {
	if _, err := New("/no/such/directory"); err == nil {
		t.Fatal("expected error for non-existent rules dir, got nil")
	}
}

// TestEvaluateScan_Accept verifies that a scan passing range thresholds and
// matching the categorical part of a rule is accepted.
func TestEvaluateScan_Accept(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0}, // 100 >= 080
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 10, // 10 >= 06
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance, got: %v", err)
	}
}

// TestEvaluateScan_Reject_LowLiveness verifies that a scan with liveness score
// below the range predicate threshold is rejected.
func TestEvaluateScan_Reject_LowLiveness(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// LivenessScore 0.5 → formatted as "050" < "080" → rejected by range rule.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 0.5},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 10,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected rejection for low liveness score, got nil error")
	}
}

// TestEvaluateScan_Reject_LowFaceMatch verifies that a scan with face match
// level below the range predicate threshold is rejected.
func TestEvaluateScan_Reject_LowFaceMatch(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// FaceMatchLevel 3 → formatted as "03" < "06" → rejected by range rule.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 3,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected rejection for low face match level, got nil error")
	}
}

// TestEvaluateScan_Reject_NoRule verifies rejection when no rule matches the
// categorical fields (document type).
func TestEvaluateScan_Reject_NoRule(t *testing.T) {
	// Only passport rule — driving licence scan must be rejected.
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel:  10,
			DocumentData:    facetec.DocumentData{DocumentType: "dl"},
			BarcodeVerified: true,
		},
	}
	if err := e.EvaluateScan(result); err == nil {
		t.Error("expected SPOCP rejection for dl with passport-only rule, got nil error")
	}
}

// TestEvaluateScan_MultipleRules verifies that a scan matching one of several
// rules is accepted.
func TestEvaluateScan_MultipleRules(t *testing.T) {
	rules := passportRule +
		"(facetec-scan (liveness-score (* range numeric ge 080)) (face-match-level (* range numeric ge 06)) (doc-type dl) (mrz-verified false) (nfc-verified false) (barcode-verified true))\n"
	dir := writeRules(t, rules)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", e.RuleCount())
	}

	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 1.0},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel:  10,
			DocumentData:    facetec.DocumentData{DocumentType: "dl"},
			BarcodeVerified: true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance for dl scan, got: %v", err)
	}
}

// TestBuildQueryElement_DocTypeFallback verifies the "unknown" fallback for empty
// DocumentType. Uses a rule that accepts any liveness/face-match and doc-type unknown.
func TestBuildQueryElement_DocTypeFallback(t *testing.T) {
	// Range ge 000 accepts all scores; ge 00 accepts all face-match levels.
	dir := writeRules(t,
		"(facetec-scan (liveness-score (* range numeric ge 000)) (face-match-level (* range numeric ge 00)) (doc-type unknown))\n",
	)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result := facetec.ScanResult{} // DocumentType empty → "unknown"
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance for unknown doc type, got: %v", err)
	}
}

// TestEvaluateScan_BoundaryLiveness_ExactThreshold verifies that a score exactly
// at the threshold is accepted (>= semantics).
func TestEvaluateScan_BoundaryLiveness_ExactThreshold(t *testing.T) {
	dir := writeRules(t, passportRule)
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// LivenessScore 0.8 → formatted as "080" == "080" → meets ge threshold.
	result := facetec.ScanResult{
		Liveness: facetec.LivenessCheckResult{LivenessScore: 0.8},
		IDScan: facetec.IDScanResult{
			FaceMatchLevel: 6,
			DocumentData:   facetec.DocumentData{DocumentType: "passport"},
			MRZVerified:    true,
		},
	}
	if err := e.EvaluateScan(result); err != nil {
		t.Errorf("expected acceptance at exact threshold, got: %v", err)
	}
}

// TestDefaultRules_RequireAuthenticatedChip loads the shipped
// rules/default.spoc and checks that its accept rules admit no document
// without an authenticated NFC chip (#65) -- including driving licences
// verified only by barcode, which the default rules used to accept. The
// review rules are covered by TestDefaultRules_ReviewRequiresAuthenticatedChip.
func TestDefaultRules_RequireAuthenticatedChip(t *testing.T) {
	e, err := New(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	scan := func(docType string, mrz, nfc, barcode bool) facetec.ScanResult {
		return facetec.ScanResult{
			Liveness: facetec.LivenessCheckResult{LivenessScore: 0.95},
			IDScan: facetec.IDScanResult{
				FaceMatchLevel:  8,
				DocumentData:    facetec.DocumentData{DocumentType: docType},
				MRZVerified:     mrz,
				NFCVerified:     nfc,
				BarcodeVerified: barcode,
			},
		}
	}

	accepted := []struct {
		name string
		scan facetec.ScanResult
	}{
		{"passport with MRZ and chip", scan("passport", true, true, false)},
		{"ID card with chip", scan("id_card", true, true, false)},
		{"ID card with chip, MRZ not verified", scan("id_card", false, true, false)},
		{"driving licence with chip", scan("dl", false, true, false)},
	}
	for _, tt := range accepted {
		if err := e.EvaluateScan(tt.scan); err != nil {
			t.Errorf("%s: want accepted, got %v", tt.name, err)
		}
	}

	rejected := []struct {
		name string
		scan facetec.ScanResult
	}{
		{"passport without chip", scan("passport", true, false, false)},
		{"passport with chip, MRZ not verified", scan("passport", false, true, false)},
		{"ID card without chip", scan("id_card", true, false, false)},
		{"driving licence with barcode, no chip", scan("dl", false, false, true)},
		{"unknown document with chip", scan("", true, true, true)},
	}
	for _, tt := range rejected {
		if err := e.EvaluateScan(tt.scan); err == nil {
			t.Errorf("%s: want rejected, got accepted", tt.name)
		}
	}
}

// TestDefaultRules_ReviewRequiresAuthenticatedChip queries the shipped
// facetec-scan-review rules directly (EvaluateScan only asks the accept
// head): a borderline scan -- below the accept thresholds, within review's --
// is escalated only when its chip was authenticated.
func TestDefaultRules_ReviewRequiresAuthenticatedChip(t *testing.T) {
	e, err := New(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	borderline := func(docType string, mrz, nfc, barcode bool) facetec.ScanResult {
		return facetec.ScanResult{
			Liveness: facetec.LivenessCheckResult{LivenessScore: 0.70},
			IDScan: facetec.IDScanResult{
				FaceMatchLevel:  5,
				DocumentData:    facetec.DocumentData{DocumentType: docType},
				MRZVerified:     mrz,
				NFCVerified:     nfc,
				BarcodeVerified: barcode,
			},
		}
	}
	review := func(r facetec.ScanResult) bool {
		return e.engine.QueryElement(buildQuery(reviewHead, r))
	}

	if err := e.EvaluateScan(borderline("passport", true, true, false)); err == nil {
		t.Fatal("a borderline scan must not pass the accept rules, or this test proves nothing")
	}

	escalated := map[string]facetec.ScanResult{
		"passport with MRZ and chip": borderline("passport", true, true, false),
		"ID card with chip":          borderline("id_card", false, true, false),
		"driving licence with chip":  borderline("dl", false, true, false),
	}
	for name, r := range escalated {
		if !review(r) {
			t.Errorf("%s: want escalated for review", name)
		}
	}

	notEscalated := map[string]facetec.ScanResult{
		"passport without chip":                 borderline("passport", true, false, false),
		"ID card without chip":                  borderline("id_card", true, false, false),
		"driving licence with barcode, no chip": borderline("dl", false, false, true),
	}
	for name, r := range notEscalated {
		if review(r) {
			t.Errorf("%s: want not escalated", name)
		}
	}
}
