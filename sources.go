// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 来源链：把"这次准入依赖了哪些材料"写成 CLC 的 SourceChain。
//
// 只声明**能证明**的：节点摘要是我们手上掌握的材料摘要（证书 DER），
// 边必须由来源自身的字节背书 —— 而 AIC 证书里虽然装着 DA，但当前解析器
// 不保留扩展的原始字节，重新编码又未必逐字节相同，所以这里**不**声称
// AIC→DA 这条边。DA 与 principal 之间的边同理留待解析器保留原始字节后再加。
//
// 未声明的边不是缺失，而是"还不能证明"；谎报才是 AEG §2.2 说的毒化。

package aicverifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/varwof/register/semantics"
)

// BuildSourceChain returns the authorization sources this admission can prove
// it rested on: the AIC (or plain leaf) certificate it verified, plus the
// principal certificate when the deployment configured one.
func BuildSourceChain(clientCert *x509.Certificate, aic *AIC, userCert *x509.Certificate) (*semantics.SourceChain, error) {
	if clientCert == nil {
		return nil, fmt.Errorf("%w: no client certificate", semantics.ErrSourceShape)
	}
	chain := semantics.SourceChain{}
	kind := "principal-cert"
	if aic != nil {
		kind = "aic-x509"
	}
	chain.Sources = append(chain.Sources, semantics.SourceRef{
		Kind:   kind,
		ID:     certID(clientCert),
		Issuer: issuerName(clientCert),
		Digest: digestOfDER(clientCert.Raw),
	})
	if userCert != nil {
		chain.Sources = append(chain.Sources, semantics.SourceRef{
			Kind:   "principal-cert",
			ID:     certID(userCert),
			Issuer: issuerName(userCert),
			Digest: digestOfDER(userCert.Raw),
		})
	}
	if err := chain.Validate(); err != nil {
		return nil, err
	}
	return &chain, nil
}

func digestOfDER(der []byte) semantics.Digest {
	sum := sha256.Sum256(der)
	return semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: sum[:]}
}

func certID(c *x509.Certificate) string {
	if c.SerialNumber != nil {
		return "serial:" + c.SerialNumber.Text(16)
	}
	return "sha256:" + hex.EncodeToString(digestOfDER(c.Raw).Value)
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}
