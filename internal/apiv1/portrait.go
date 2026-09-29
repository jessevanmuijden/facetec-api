package apiv1

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/jpeg"

	jpeg2000 "github.com/mrjoshuak/go-jpeg2000"
)

// portraitJPEGQuality is the quality a JPEG 2000 portrait is re-encoded at.
const portraitJPEGQuality = 90

var (
	// jp2Signature starts a JP2 file (ISO/IEC 15444-1 Annex I signature box).
	jp2Signature = []byte{0x00, 0x00, 0x00, 0x0c, 'j', 'P', ' ', ' ', 0x0d, 0x0a, 0x87, 0x0a}
	// j2kSignature starts a raw JPEG 2000 codestream (SOC followed by SIZ).
	j2kSignature = []byte{0xff, 0x4f, 0xff, 0x51}
)

// portraitAsJPEG returns a base64 portrait as a base64 JPEG.
//
// ICAO 9303 lets the DG2 face image be JPEG or JPEG 2000, and many European
// passports use JPEG 2000. Both are valid ISO 23220 portraits, but no browser
// engine (including Android's WebView, which renders the wallet's credential
// card) can display JPEG 2000, so it is transcoded here. JPEG and anything
// that is not recognisably JPEG 2000 is returned unchanged, as is a JPEG 2000
// image that fails to decode: an undisplayable portrait is still a correct one.
func portraitAsJPEG(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return b64
	}
	if !bytes.HasPrefix(raw, jp2Signature) && !bytes.HasPrefix(raw, j2kSignature) {
		return b64
	}

	img, err := decodeJPEG2000(raw)
	if err != nil {
		return b64
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: portraitJPEGQuality}); err != nil {
		return b64
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// decodeJPEG2000 decodes a JP2 file or J2K codestream, converting a decoder
// panic on malformed input into an error.
func decodeJPEG2000(raw []byte) (img image.Image, err error) {
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, errPortraitDecode
		}
	}()
	return jpeg2000.Decode(bytes.NewReader(raw))
}

var errPortraitDecode = errors.New("apiv1: JPEG 2000 portrait could not be decoded")
