package apiv1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jpeg2000 "github.com/mrjoshuak/go-jpeg2000"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/facetec"
	"github.com/sirosfoundation/facetec-api/internal/issuerclient"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

var photoIDNow = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

func photoIDDocument() facetec.DocumentData {
	return facetec.DocumentData{
		GivenName:      "Willeke Liselotte",
		FamilyName:     "De Bruijn",
		DocumentNumber: "SPECI2021",
		DateOfBirth:    "1965-03-10",
		DateOfExpiry:   "2031-08-02",
		Nationality:    "NLD",
		Sex:            "F",
		IssuingCountry: "NLD",
		DocumentType:   "passport",
		MRZLine1:       "P<NLDDE<BRUIJN<<WILLEKE<LISELOTTE<<<<<<<<<<<",
		Portrait:       base64.StdEncoding.EncodeToString(testJPEG(testImage())),
	}
}

func testImage() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 16, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 12), B: 128, A: 255})
		}
	}
	return img
}

func testJPEG(img image.Image) []byte {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestMapPhotoIDClaims(t *testing.T) {
	doc := photoIDDocument()
	claims := MapPhotoIDClaims(doc, "ft-abc", PhotoIDIssuer{Authority: "SIROS Foundation", Country: "se"}, photoIDNow)

	assert.Equal(t, map[string]any{
		"family_name_unicode":       "De Bruijn",
		"given_name_unicode":        "Willeke Liselotte",
		"birth_date":                "1965-03-10",
		"portrait":                  doc.Portrait,
		"issue_date":                "2026-09-29",
		"expiry_date":               "2031-08-02",
		"issuing_authority_unicode": "SIROS Foundation",
		"issuing_country":           "SE",
		"sex":                       2,
		"nationality":               "NL",
		"document_number":           "ft-abc",
		"age_over_18":               true,
		"age_in_years":              61,
		"age_birth_year":            1965,
		"travel_document_number":    "SPECI2021",
	}, claims)
}

func TestMapPhotoIDClaims_IssuingCountryFallsBackToDocument(t *testing.T) {
	claims := MapPhotoIDClaims(photoIDDocument(), "ft-abc", PhotoIDIssuer{Authority: "x"}, photoIDNow)
	assert.Equal(t, "NL", claims["issuing_country"])
}

func TestMapPhotoIDClaims_AgeTurnsOnBirthday(t *testing.T) {
	doc := photoIDDocument()
	doc.DateOfBirth = "2008-09-30"
	claims := MapPhotoIDClaims(doc, "ft-abc", PhotoIDIssuer{}, photoIDNow)
	assert.Equal(t, false, claims["age_over_18"])
	assert.Equal(t, 17, claims["age_in_years"])

	claims = MapPhotoIDClaims(doc, "ft-abc", PhotoIDIssuer{}, photoIDNow.Add(24*time.Hour))
	assert.Equal(t, true, claims["age_over_18"])
	assert.Equal(t, 18, claims["age_in_years"])
}

// An unparseable date must be left out rather than forwarded: the vc issuer
// encodes these as CBOR full-dates, and a mandatory one that is missing fails
// issuance loudly instead of producing a malformed credential.
func TestMapPhotoIDClaims_UnparseableDatesOmitted(t *testing.T) {
	doc := photoIDDocument()
	doc.DateOfBirth = "10 MAA 1965"
	doc.DateOfExpiry = ""
	doc.Portrait = ""
	claims := MapPhotoIDClaims(doc, "ft-abc", PhotoIDIssuer{}, photoIDNow)
	for _, k := range []string{"birth_date", "age_over_18", "age_in_years", "age_birth_year", "expiry_date", "portrait"} {
		assert.NotContains(t, claims, k)
	}
}

func TestMapPhotoIDClaims_ExcludesMRZ(t *testing.T) {
	data, err := json.Marshal(MapPhotoIDClaims(photoIDDocument(), "ft-abc", PhotoIDIssuer{}, photoIDNow))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "NLDDE<BRUIJN")
}

func TestPortraitAsJPEG_TranscodesJPEG2000(t *testing.T) {
	var jp2 bytes.Buffer
	require.NoError(t, jpeg2000.Encode(&jp2, testImage(), nil))
	require.True(t, bytes.HasPrefix(jp2.Bytes(), jp2Signature) || bytes.HasPrefix(jp2.Bytes(), j2kSignature))

	out, err := base64.StdEncoding.DecodeString(portraitAsJPEG(base64.StdEncoding.EncodeToString(jp2.Bytes())))
	require.NoError(t, err)
	img, err := jpeg.Decode(bytes.NewReader(out))
	require.NoError(t, err)
	assert.Equal(t, image.Rect(0, 0, 16, 20), img.Bounds())
}

func TestPortraitAsJPEG_LeavesOthersUnchanged(t *testing.T) {
	jpg := base64.StdEncoding.EncodeToString(testJPEG(testImage()))
	assert.Equal(t, jpg, portraitAsJPEG(jpg))

	assert.Equal(t, "not base64!", portraitAsJPEG("not base64!"))

	// Carries a JP2 signature but no decodable image.
	broken := base64.StdEncoding.EncodeToString(append(append([]byte{}, jp2Signature...), 0x01, 0x02))
	assert.Equal(t, broken, portraitAsJPEG(broken))
}

// TestIssueCredential_MdocUploadsPhotoID verifies that an mdoc tenant uploads
// the RFC013 Photo ID elements instead of the flat sdjwt claims.
func TestIssueCredential_MdocUploadsPhotoID(t *testing.T) {
	var uploadBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/datastore":
			_ = json.Unmarshal(body, &uploadBody)
		case "/api/v1/datastore/preauth_offer":
			_ = json.NewEncoder(w).Encode(issuerclient.PreauthOfferReply{CredentialOfferURL: "openid-credential-offer://?x=1"})
		}
	}))
	defer srv.Close()

	issuerClient, err := issuerclient.New(issuerclient.Config{BaseURL: srv.URL})
	require.NoError(t, err)
	c := &Client{
		cfg:    &config.Config{Issuer: config.IssuerConfig{AuthenticSource: "facetec"}},
		log:    zap.NewNop(),
		issuer: issuerClient,
	}

	scan := facetec.ScanResult{IDScan: facetec.IDScanResult{DocumentData: photoIDDocument()}}
	docID, _, err := c.issueCredential(t.Context(), scan, tenant.IssuerParams{Scope: "photoid", Format: "mdoc"})
	require.NoError(t, err)

	dd := uploadBody["document_data"].(map[string]any)
	assert.Equal(t, "De Bruijn", dd["family_name_unicode"])
	assert.Equal(t, "facetec", dd["issuing_authority_unicode"], "authority defaults to the authentic source")
	assert.Equal(t, docID, dd["document_number"])
	assert.Equal(t, "SPECI2021", dd["travel_document_number"])
	assert.NotContains(t, dd, "given_name")
}
