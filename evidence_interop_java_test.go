// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 与 Java SDK（aic-lib-java 的 com.varwof.audit.RecordSigner）的证据签名互操作。
//
// 这些向量由 Java 侧产出：RecordSigner.of(keyId, private, public).sign(
// Envelope.PAE(payloadType, payload))，JDK 17。所以这里校验的是相反的方向——
// Go 必须能验证 Java 签出来的字节。aic-lib-java 的 EvidenceSigningInteropTest
// 校验的是 Go→Java；两个方向合起来，才能发现"某一侧把 PAE 多哈希了一次"这类
// 只在单向比较里看不见的分歧。
//
// PAE 与 Ed25519 签名是确定性的，逐字节相等才是有意义的断言；ECDSA 与 RSA
// 签名带随机数，只断言"能验签"。

package aicverifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

const javaPayloadType = "application/vnd.in-toto+json"

// 与 Java 侧 EvidenceSigningInteropTest 的 PAYLOAD 逐字节相同。
var javaPayload = []byte(`{"ver":"CLC-1.15","verdict":"allow"}`)

const (
	javaPaeHex = "445353457631203238206170706c69636174696f6e2f766e642e696e2d746f746f2b6a736f6e203336207b22766572223a22434c432d312e3135222c2276657264696374223a22616c6c6f77227d"

	javaECSignatureDER = "3045022100fcfd29528193cd9ca642178d79e4a514bf53534091b0db63be146038dd6e7dcc022062284fa75c2239d63148b4b809605b0d30b5d28cfba4925db217307926f32649"
	javaECSignatureRAW = "fcfd29528193cd9ca642178d79e4a514bf53534091b0db63be146038dd6e7dcc62284fa75c2239d63148b4b809605b0d30b5d28cfba4925db217307926f32649"
	javaEDSignature    = "4756c25cf44427dfae5ad6364d3977a166edb1794f4d56eb6062b8dbd4cc0e6e3a54e35ae6a119c325a61407d2e7b4a746cf004ff8788167e3f715d755b33106"
	javaRSASignature   = "2da550a4d5003abebc35dcacb045d221b1a00fcee4530aec0f6bcb2ceb5b6569b16dfc8f682ed791bcbda58d26fae9d095d2c7d47eb6fd8f077e9e340921884d9e869575cd7d6174cd689da0add07ff6d95484b441baca343abe162947eb9b6a6398c267592a45577025820a34ef31b52f1aa5da8219111475d1dc7cf66618279fcbbeba13d226e42f31c35b3064d7111d8f8a971f3a77fd68ed93cc0cd12a818d1cc2fed15d8f73d609e69a2dc9b047bb44799990c4dae258707f036ffab750caa93cc6fe851cfdc589d0506cf3ab019d101008cb866cf91309f352985be960da496d880d06a73aea9de117ea16d32d6e0327f194d1d0bfc1fec4b7ccbef875"

	javaECPrivatePEM = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBEhIE09Wy000uPX7s4
cJYtXb7tkKFuR+Cu75msHFU9zw==
-----END PRIVATE KEY-----`
	javaEDPrivatePEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIITUMfgo1v5EF8bzMsSAe8oBln0x9cxNlzBDLzP4tuHR
-----END PRIVATE KEY-----`

	javaECPublicPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgM4gvArCyP4BtmLtKFR6NZ2XIksi
baQKMuAVM6ilnh1jjzCburSrJmnu1evBOJG2IfvyxqDKcwSZ//hd6gaQTw==
-----END PUBLIC KEY-----`
	javaEDPublicPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAgRVJWn4pxkYXerOW0Lzqly1pIiSCU3Bc0Sjzy+f3MdA=
-----END PUBLIC KEY-----`
	javaRSAPublicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyogNFi1mnVmLQgEPusxD
jwSE4EcBYrx5fcwIVugx6IM7gw170JGob1AKHXtjjT5HszK0ol6rFlYlYxDCHRVZ
xYNBCceTYCWs/7U0vI0YDNhxe4IrJZ1+aUROqgYKPIFOY+axigY+/Qia0+HrW7+M
EKQQbP9vktSA2PBWsUaJSONWP/Zfu/LvVArMw+bpIVmkTXK2P2rWlK/EB0KhZ8qo
Zd48HIA+j3P0tob4CkxGJCCGZj+tBkSOcs9GQdTSNzzvI4ZYOKZzwPiZS2MB8f4Q
qaAGeXHOz+Q3qAE6XqPTKxQc4RUcyJnzVry79dRMF6v7FpZ+VQAdmesemA7NBmv/
HwIDAQAB
-----END PUBLIC KEY-----`
)

func TestJavaEvidenceSignaturesVerifyHere(t *testing.T) {
	pae := semantics.PAE(javaPayloadType, javaPayload)

	t.Run("PAE", func(t *testing.T) {
		if got := hex.EncodeToString(pae); got != javaPaeHex {
			t.Fatalf("PAE differs from Java's:\n got %s\nwant %s", got, javaPaeHex)
		}
	})

	t.Run("ECDSADER", func(t *testing.T) {
		key := javaSigner(t, javaECPrivatePEM)
		verify := VerifyFnFromKey(key.Public())
		if err := verify("pep-1", pae, mustHex(t, javaECSignatureDER)); err != nil {
			t.Fatalf("Java's DER ECDSA signature does not verify: %v", err)
		}
		// Java 发布的公钥必须就是它签名的那把：两侧各自算一遍，比对公钥本身。
		if !sameECDSAKey(key.Public(), javaPublic(t, javaECPublicPEM)) {
			t.Fatal("the public key Java published is not the one it signed with")
		}
	})

	t.Run("ECDSARaw", func(t *testing.T) {
		// 对端可能给出 r||s 而非 DER，splitDSSESignature 与验签回调都得吃下。
		raw := mustHex(t, javaECSignatureRAW)
		if err := VerifyFnFromKey(javaPublic(t, javaECPublicPEM))("pep-1", pae, raw); err != nil {
			t.Fatalf("Java's raw r||s signature does not verify: %v", err)
		}
		r, s := splitDSSESignature(raw)
		if r == nil || s == nil {
			t.Fatal("Java's raw form was not read as an r||s pair")
		}
		digest := sha256.Sum256(pae)
		if !ecdsa.Verify(javaPublic(t, javaECPublicPEM).(*ecdsa.PublicKey), digest[:], r, s) {
			t.Fatal("the r and s read out of Java's raw form do not verify")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		digest := sha256.Sum256(pae)
		pub := javaPublic(t, javaRSAPublicPEM).(*rsa.PublicKey)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], mustHex(t, javaRSASignature)); err != nil {
			t.Fatalf("Java's RSA signature does not verify: %v", err)
		}
		if err := VerifyFnFromKey(pub)("pep-1", pae, mustHex(t, javaRSASignature)); err != nil {
			t.Fatalf("the evidence verifier rejected Java's RSA signature: %v", err)
		}
	})

	t.Run("Ed25519IsIdentical", func(t *testing.T) {
		key := javaSigner(t, javaEDPrivatePEM)
		signer, err := NewRecordSigner("pep-1", key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := signer.Sign(pae)
		if err != nil {
			t.Fatal(err)
		}
		// Ed25519 确定性：同一密钥同一消息，两侧必须给出同一串字节。
		if !bytes.Equal(got, mustHex(t, javaEDSignature)) {
			t.Fatalf("Ed25519 signatures differ:\n got %x\nwant %s", got, javaEDSignature)
		}
		pub := javaPublic(t, javaEDPublicPEM)
		if !ed25519.Verify(pub.(ed25519.PublicKey), pae, got) {
			t.Fatal("the Ed25519 signature does not verify under the key Java wrote")
		}
	})
}

func javaSigner(t *testing.T, pemText string) crypto.Signer {
	t.Helper()
	key, err := ParsePrivateKeyPEM([]byte(strings.TrimSpace(pemText) + "\n"))
	if err != nil {
		t.Fatalf("cannot read the private key Java wrote: %v", err)
	}
	return key
}

func javaPublic(t *testing.T, pemText string) crypto.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatal("no PEM block in the key Java wrote")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("cannot read the public key Java wrote: %v", err)
	}
	return pub
}

func sameECDSAKey(a crypto.PublicKey, b crypto.PublicKey) bool {
	x, ok1 := a.(*ecdsa.PublicKey)
	y, ok2 := b.(*ecdsa.PublicKey)
	return ok1 && ok2 && x.Equal(y)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector is not hex: %v", err)
	}
	return b
}
