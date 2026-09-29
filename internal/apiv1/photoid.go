package apiv1

import (
	"strings"
	"time"

	"github.com/sirosfoundation/facetec-api/internal/facetec"
)

// PhotoIDIssuer describes the party that issues the Photo ID attestation.
// Under EWC RFC013 the attestation is issued by the QTSP that performed the
// identity proofing, not by the authority that issued the scanned passport,
// so these values come from configuration rather than from the document.
type PhotoIDIssuer struct {
	// Authority is the org.iso.23220.1 issuing_authority_unicode value.
	Authority string
	// Country is the org.iso.23220.1 issuing_country value (ISO 3166-1
	// alpha-2). When empty, the scanned document's issuing country is used.
	Country string
}

// MapPhotoIDClaims converts a DocumentData to the flat data-element map the
// vc apigw needs to issue an EWC RFC013 Photo ID (doctype
// eu.europa.ec.eudi.photoid.1, ISO/IEC TS 23220-4 Annex C) as an mso_mdoc.
//
// The map is flat because the vc issuer places each element into its
// namespace (org.iso.23220.1 or org.iso.23220.photoid.1) from the MDDL
// schema. Dates are ISO 8601 full-dates, portrait is the base64 image the
// issuer decodes into a bstr, and sex is an ISO/IEC 5218 integer.
//
// issue_date and expiry_date describe the attestation itself: it is issued
// now and expires with the travel document it was derived from. The passport
// number is carried as travel_document_number; document_number identifies
// the attestation, so it is set to documentID.
//
// Only the elements the RFC013 schema declares are produced. MRZ lines and
// raw NFC data groups (the optional org.iso.23220.dtc.1 namespace) are
// excluded by design and never leave this service.
func MapPhotoIDClaims(doc facetec.DocumentData, documentID string, issuer PhotoIDIssuer, now time.Time) map[string]any {
	now = now.UTC()
	issuingCountry := toISO3166Alpha2(issuer.Country)
	if issuingCountry == "" {
		issuingCountry = toISO3166Alpha2(doc.IssuingCountry)
	}

	claims := map[string]any{
		// org.iso.23220.1
		"family_name_unicode":       doc.FamilyName,
		"given_name_unicode":        doc.GivenName,
		"issue_date":                now.Format("2006-01-02"),
		"issuing_authority_unicode": issuer.Authority,
		"issuing_country":           issuingCountry,
		"sex":                       mapSexToISO5218(doc.Sex),
		"document_number":           documentID,
		// org.iso.23220.photoid.1
		"travel_document_number": doc.DocumentNumber,
	}

	if birth, ok := parseISODate(doc.DateOfBirth); ok {
		claims["birth_date"] = birth.Format("2006-01-02")
		age := ageInYears(birth, now)
		claims["age_over_18"] = age >= 18
		claims["age_in_years"] = age
		claims["age_birth_year"] = birth.Year()
	}
	if expiry, ok := parseISODate(doc.DateOfExpiry); ok {
		claims["expiry_date"] = expiry.Format("2006-01-02")
	}
	if nationality := toISO3166Alpha2(doc.Nationality); nationality != "" {
		claims["nationality"] = nationality
	}
	if doc.Portrait != "" {
		// portrait_capture_date is left out: the image is the one on the
		// document's chip, and its capture date is not known here.
		claims["portrait"] = portraitAsJPEG(doc.Portrait)
	}

	return claims
}

// parseISODate parses a YYYY-MM-DD date, the form DocumentData carries.
func parseISODate(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// ageInYears returns the number of whole years between birth and now.
func ageInYears(birth, now time.Time) int {
	age := now.Year() - birth.Year()
	if now.Month() < birth.Month() || (now.Month() == birth.Month() && now.Day() < birth.Day()) {
		age--
	}
	return age
}
