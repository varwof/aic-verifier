// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

var oidSha256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// CMS signedAttrs attribute OIDs (RFC 5652 §11).
var (
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// TimeStampReq is an RFC 3161 timestamp request.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *int                  `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []asn1.RawValue       `asn1:"optional,set"`
}

// MessageImprint is a message digest imprint.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampResp is an RFC 3161 timestamp response.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo is PKI status information.
type PKIStatusInfo struct {
	Status int
}

// TSTInfo is the timestamp token information.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   int
	GenTime        time.Time
	Accuracy       asn1.RawValue `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *int          `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// ContentInfo is CMS content information.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsEncapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// cmsSignerInfo holds the parsed fields needed to verify a CMS SignerInfo signature.
type cmsSignerInfo struct {
	DigestAlgorithm asn1.ObjectIdentifier
	SignatureAlgo   asn1.ObjectIdentifier
	SignedAttrsRaw  []byte // raw DER of [0] IMPLICIT SignedAttributes (including tag)
	// SignedAttrsSet is the RFC 5652 §5.4 SET OF encoding of SignedAttributes,
	// which is the value the signature is computed over (not the [0] form).
	SignedAttrsSet []byte
	// MessageDigest is the value of the message-digest attribute (digest of the
	// encapContent), used to cross-check the timestamped data (finding 9).
	MessageDigest []byte
	// ContentType is the value of the contentType attribute (must be
	// id-ct-TSTInfo for RFC 3161).
	ContentType    asn1.ObjectIdentifier
	SignatureValue []byte
}

// cmsAttribute is a single CMS signedAttr Attribute.
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// parseSignedAttrs decodes an RFC 5652 SignedAttributes SET OF into its
// Attributes. data must be the DER-encoded SET OF (starting with tag 0x31).
func parseSignedAttrs(data []byte) ([]cmsAttribute, error) {
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	if set.Tag != asn1.TagSet {
		return nil, fmt.Errorf("expected SET OF for SignedAttributes, got tag %d", set.Tag)
	}
	var rest = set.Bytes
	var attrs []cmsAttribute
	for len(rest) > 0 {
		var el asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &el)
		if err != nil {
			return nil, err
		}
		var a cmsAttribute
		if _, err := asn1.Unmarshal(el.FullBytes, &a); err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
		rest = remaining
	}
	return attrs, nil
}

// TSAClient is an RFC 3161 timestamp client.
type TSAClient struct {
	// URL is the TSA service address.
	URL string
	// CACert is the CA certificate (for verifying TSA response signatures).
	CACert *x509.Certificate
	// HTTPClient is the HTTP client.
	HTTPClient *http.Client
	// SignFunc is a custom signing function (replaces HTTP calls).
	SignFunc func(data []byte) ([]byte, error)
	// maxTSTAge bounds how old a timestamp token may be and still be accepted
	// (L7). A tight window limits replay/backdating of audit timestamps.
	maxTSTAge time.Duration
}

// SetMaxTSTAge overrides the accepted TST age window. Defaults to 1h.
func (t *TSAClient) SetMaxTSTAge(d time.Duration) {
	if t == nil {
		return
	}
	t.maxTSTAge = d
}

// NewTSAClient creates a timestamp client.
func NewTSAClient(url string) *TSAClient {
	if url == "" {
		return nil
	}
	return &TSAClient{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		maxTSTAge:  time.Hour,
	}
}

// SetCACert sets the TSA CA certificate.
func (t *TSAClient) SetCACert(certFile string) error {
	if t == nil {
		return nil
	}
	if certFile == "" {
		return nil
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read TSA CA cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM data in TSA CA cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse TSA CA cert: %w", err)
	}
	t.CACert = cert
	return nil
}

// Sign performs an RFC 3161 timestamp signature on data.
func (t *TSAClient) Sign(data []byte) (tstDER []byte, err error) {
	if t == nil {
		return nil, fmt.Errorf("tsa client not configured")
	}

	if t.SignFunc != nil {
		return t.SignFunc(data)
	}

	hashed := sha256.Sum256(data)
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: oidSha256},
			HashedMessage: hashed[:],
		},
		CertReq: true,
	}

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal TSA request: %w", err)
	}

	contentInfo := ContentInfo{
		ContentType: oidTSTInfo,
		Content:     asn1.RawValue{FullBytes: reqDER},
	}
	body, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal ContentInfo: %w", err)
	}

	respBody, err := t.postTSA(body)
	if err != nil {
		return nil, err
	}

	var tsResp TimeStampResp
	if _, err := asn1.Unmarshal(respBody, &tsResp); err != nil {
		return nil, fmt.Errorf("parse TSA response: %w", err)
	}
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		return nil, fmt.Errorf("TSA status: %d", tsResp.Status.Status)
	}

	return tsResp.TimeStampToken.FullBytes, nil
}

// Verify verifies a timestamp token.
func (t *TSAClient) Verify(entryJSON, tstDER []byte) error {
	if t == nil {
		return fmt.Errorf("tsa client not configured")
	}

	tstInfo, certs, signerInfo, eContent, err := extractTSTInfoFromCMS(tstDER)
	if err != nil {
		return fmt.Errorf("extract TSTInfo: %w", err)
	}

	expected := sha256.Sum256(entryJSON)
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, expected[:]) {
		return fmt.Errorf("hash mismatch: data not original")
	}

	now := time.Now()
	if tstInfo.GenTime.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("TST generation time is in the future: %v", tstInfo.GenTime)
	}
	// L7: tighten the accepted age from 24h to maxTSTAge (default 1h) to limit
	// replay/backdating of audit timestamps.
	if tstInfo.GenTime.Before(now.Add(-t.maxTSTAge)) {
		return fmt.Errorf("TST generation time is too old ( >%s): %v", t.maxTSTAge, tstInfo.GenTime)
	}

	// G4 fix: CACert is now mandatory — without a trust anchor we cannot
	// verify the CMS signature, making the entire timestamp token unverifiable.
	if t.CACert == nil {
		return fmt.Errorf("TSA CA certificate not configured — cannot verify timestamp token")
	}

	if len(certs) == 0 {
		return fmt.Errorf("no TSA certificate found in CMS response")
	}
	if err := verifyTSACertChain(certs, t.CACert); err != nil {
		return fmt.Errorf("TSA certificate chain verification failed: %w", err)
	}

	// G4 fix: verify the CMS SignerInfo signature over the timestamp data.
	if err := verifyCMSSignature(signerInfo, certs, eContent); err != nil {
		return fmt.Errorf("CMS signature verification failed: %w", err)
	}

	return nil
}

func extractTSTInfoFromCMS(tstDER []byte) (*TSTInfo, []*x509.Certificate, *cmsSignerInfo, []byte, error) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(tstDER, &ci); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse CMS ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, nil, nil, nil, fmt.Errorf("expected id-signedData (%v), got %v", oidSignedData, ci.ContentType)
	}

	sdRaw, err := parseRawValue(ci.Content.Bytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse SignedData SEQUENCE: %w", err)
	}
	if sdRaw.Tag != asn1.TagSequence {
		return nil, nil, nil, nil, fmt.Errorf("expected SEQUENCE for SignedData")
	}

	rest := sdRaw.Bytes

	var raw asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse signedData version: %w", err)
	}
	if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse digestAlgorithms: %w", err)
	}

	var eciRaw asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &eciRaw); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse encapContentInfo: %w", err)
	}

	var eci cmsEncapContentInfo
	if _, err := asn1.Unmarshal(eciRaw.Bytes, &eci); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse encapContentInfo inner: %w", err)
	}
	if !eci.ContentType.Equal(oidTSTInfo) {
		return nil, nil, nil, nil, fmt.Errorf("expected id-ct-TSTInfo (%v), got %v", oidTSTInfo, eci.ContentType)
	}
	if len(eci.Content.Bytes) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("missing eContent (TSTInfo octets)")
	}
	// eci.Content.Bytes is the encapContentInfo eContent octets (the TSTInfo DER);
	// both the TSTInfo parse and the message-digest cross-check use these bytes.
	eContent := eci.Content.Bytes

	var tstInfo TSTInfo
	if _, err := asn1.Unmarshal(eContent, &tstInfo); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse TSTInfo: %w", err)
	}

	var certs []*x509.Certificate
	if len(rest) > 0 && rest[0] == 0xA0 {
		if _, err := asn1.Unmarshal(rest, &raw); err == nil {
			certs = parseCertificatesFromRaw(raw.Bytes)
			rest = rest[len(rest)-len(rest):] // clear rest after consuming certs
		}
	}

	// Parse signerInfos (SET OF SignerInfo) — the last element of SignedData.
	var signerInfo *cmsSignerInfo
	if len(rest) > 0 {
		var signerInfosRaw asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &signerInfosRaw); err == nil && signerInfosRaw.Tag == asn1.TagSet {
			// Extract first SignerInfo from the SET
			if len(signerInfosRaw.Bytes) > 0 {
				var siRaw asn1.RawValue
				if _, err := asn1.Unmarshal(signerInfosRaw.Bytes, &siRaw); err == nil {
					signerInfo = parseSignerInfo(siRaw.Bytes)
				}
			}
		}
	}

	return &tstInfo, certs, signerInfo, eContent, nil
}

func parseRawValue(data []byte) (*asn1.RawValue, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &raw, nil
}

func parseCertificatesFromRaw(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate

	var setElements []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &setElements); err == nil {
		for _, el := range setElements {
			if c, err := x509.ParseCertificate(el.FullBytes); err == nil {
				certs = append(certs, c)
			}
		}
		if len(certs) > 0 {
			return certs
		}
	}

	rest := data
	for len(rest) > 0 {
		var el asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &el)
		if err != nil {
			break
		}
		if c, err := x509.ParseCertificate(el.FullBytes); err == nil {
			certs = append(certs, c)
		}
		rest = remaining
	}

	return certs
}

func verifyTSACertChain(certs []*x509.Certificate, caCert *x509.Certificate) error {
	leaf := findTSACert(certs)
	if leaf == nil {
		return fmt.Errorf("no suitable TSA certificate found (missing ExtendedKeyUsageTimeStamping)")
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	intermediates := x509.NewCertPool()
	for _, c := range certs {
		if c != leaf {
			intermediates.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   time.Now(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	return nil
}

func findTSACert(certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		for _, ku := range c.ExtKeyUsage {
			if ku == x509.ExtKeyUsageTimeStamping {
				return c
			}
		}
	}
	for _, c := range certs {
		if !c.IsCA {
			return c
		}
	}
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// parseSignerInfo parses a CMS SignerInfo DER sequence.
//
//	SignerInfo ::= SEQUENCE {
//	  version INTEGER,
//	  sid SignerIdentifier,
//	  digestAlgorithm DigestAlgorithmIdentifier,
//	  signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//	  signatureAlgorithm AlgorithmIdentifier,
//	  signature OCTET STRING
//	}
func parseSignerInfo(data []byte) *cmsSignerInfo {
	var rest = data
	var raw asn1.RawValue

	// version
	rest, _ = asn1.Unmarshal(rest, &raw)
	// sid (issuerAndSerialNumber or subjectKeyIdentifier)
	rest, _ = asn1.Unmarshal(rest, &raw)
	// digestAlgorithm
	var digestAlgo asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &digestAlgo)
	digestOID := parseAlgorithmOID(digestAlgo.FullBytes)

	// signedAttrs [0] IMPLICIT — optional
	var signedAttrsRaw []byte
	si := &cmsSignerInfo{}
	if len(rest) > 0 && rest[0] == 0xa0 {
		rest, _ = asn1.Unmarshal(rest, &raw)
		signedAttrsRaw = raw.FullBytes
		si.SignedAttrsRaw = signedAttrsRaw
		// RFC 5652 §5.4: the signature is over the DER encoding of SignedAttributes
		// as a SET OF (tag 0x31), not the [0] IMPLICIT wrapper (tag 0xA0).
		// Iterate the SET content manually (Go's asn1 cannot unmarshal a SET OF
		// directly into a struct slice).
		if attrs, err := parseSignedAttrs(raw.Bytes); err == nil {
			if set, err := asn1.MarshalWithParams(attrs, "set"); err == nil {
				si.SignedAttrsSet = set
			}
			for _, a := range attrs {
				switch {
				case a.Type.Equal(oidContentType) && len(a.Values) == 1:
					var oid asn1.ObjectIdentifier
					if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &oid); err == nil {
						si.ContentType = oid
					}
				case a.Type.Equal(oidMessageDigest) && len(a.Values) == 1:
					// message-digest value is an OCTET STRING; RawValue.Bytes is
					// the octet content.
					si.MessageDigest = a.Values[0].Bytes
				}
			}
		}
	}

	// signatureAlgorithm
	var sigAlgo asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &sigAlgo)
	sigOID := parseAlgorithmOID(sigAlgo.FullBytes)

	// signature (OCTET STRING)
	rest, _ = asn1.Unmarshal(rest, &raw)

	si.DigestAlgorithm = digestOID
	si.SignatureAlgo = sigOID
	si.SignatureValue = raw.Bytes

	return si
}

// parseAlgorithmOID extracts the OID from a DER-encoded AlgorithmIdentifier.
func parseAlgorithmOID(data []byte) asn1.ObjectIdentifier {
	var algo struct {
		OID asn1.ObjectIdentifier
	}
	if _, err := asn1.Unmarshal(data, &algo); err != nil {
		return nil
	}
	return algo.OID
}

// verifyCMSSignature verifies the CMS SignerInfo signature. Per RFC 5652 §5.4
// and RFC 3161 §2.4.2, when signedAttrs are present the signature is computed
// over the DER encoding of the SignedAttributes SET OF, and the signed
// message-digest attribute must equal the digest of the encapContentInfo
// eContent. Both are enforced here (finding 9).
func verifyCMSSignature(si *cmsSignerInfo, certs []*x509.Certificate, eContent []byte) error {
	if si == nil {
		return fmt.Errorf("no SignerInfo to verify")
	}

	// Find the signer certificate by matching the digest algorithm's key
	// (simplified: use the TSA cert found by EKU)
	signer := findTSACert(certs)
	if signer == nil {
		return fmt.Errorf("no TSA signer certificate found")
	}

	hasher := crypto.SHA256
	if si.SignedAttrsSet != nil {
		// contentType must be id-ct-TSTInfo (RFC 3161 §2.4.2).
		if !si.ContentType.Equal(oidTSTInfo) {
			return fmt.Errorf("signedAttrs contentType attribute: got %v, want id-ct-TSTInfo", si.ContentType)
		}
		// message-digest must equal digest of eContent (RFC 5652 §5.4).
		h := hasher.New()
		h.Write(eContent)
		if !bytes.Equal(si.MessageDigest, h.Sum(nil)) {
			return fmt.Errorf("signedAttrs message-digest does not match eContent")
		}
	}

	// Compute the data the signature covers: the signedAttrs SET OF encoding
	// when present, otherwise the eContent.
	toVerify := si.SignedAttrsSet
	if toVerify == nil {
		toVerify = eContent
	}

	h := hasher.New()
	h.Write(toVerify)
	digest := h.Sum(nil)

	// Verify signature based on algorithm
	switch {
	case si.SignatureAlgo.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}): // ecdsa-with-SHA256
		return verifyECDSASignatureRaw(digest, si.SignatureValue, signer)
	case si.SignatureAlgo.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}): // sha256WithRSAEncryption
		return verifyRSASignatureRaw(digest, si.SignatureValue, signer)
	default:
		return fmt.Errorf("unsupported CMS signature algorithm: %v", si.SignatureAlgo)
	}
}

func verifyECDSASignatureRaw(digest, signature []byte, cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not ECDSA")
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("unmarshal ECDSA signature: %w", err)
	}
	if !ecdsa.Verify(pub, digest, sig.R, sig.S) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

func verifyRSASignatureRaw(digest, signature []byte, cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, signature)
}

func (t *TSAClient) postTSA(reqData []byte) ([]byte, error) {
	httpReq, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	httpResp, err := t.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("TSA HTTP POST: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read TSA response: %w", err)
	}

	return body, nil
}

// MarshalTSARequest serializes a TSA request to DER.
func MarshalTSARequest(req TimeStampReq) ([]byte, error) {
	return asn1.Marshal(req)
}

// UnmarshalTimestampToken parses a timestamp token from DER.
func UnmarshalTimestampToken(data []byte) (*TSTInfo, error) {
	tstInfo, _, _, _, err := extractTSTInfoFromCMS(data)
	return tstInfo, err
}

// EncodeBase64 performs Base64 encoding.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 performs Base64 decoding.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
