// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/policylabs/signer/key"
)

// keyBundleMediaType is the bundle version key-signed bundles declare.
// sigstore-go accepts a certificate chain at v0.3 when parsing with
// bundle.AllowCertificateChain, which the signer's own parsers pass.
const keyBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// bundleFromEnvelope wraps a key-signed DSSE envelope in a sigstore
// bundle carrying the given verification material.
func bundleFromEnvelope(env *sdsse.Envelope, material *protobundle.VerificationMaterial) *sbundle.Bundle {
	return &sbundle.Bundle{
		Bundle: &protobundle.Bundle{
			MediaType:            keyBundleMediaType,
			VerificationMaterial: material,
			Content:              &protobundle.Bundle_DsseEnvelope{DsseEnvelope: env},
		},
	}
}

// keyVerificationMaterial builds the verification material of a bundle
// signed with k: the certificate chain when one is given, otherwise a
// hint that identifies the public key.
func keyVerificationMaterial(k key.PrivateKeyProvider, chain []*x509.Certificate) (*protobundle.VerificationMaterial, error) {
	priv, err := k.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	if priv == nil {
		return nil, errors.New("signing key provider returned no key")
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("deriving public key: %w", err)
	}

	if len(chain) == 0 {
		hint, err := publicKeyHint(pub)
		if err != nil {
			return nil, err
		}
		return &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: hint},
			},
		}, nil
	}

	certs, err := chainCertificates(pub, chain)
	if err != nil {
		return nil, err
	}
	return &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certs},
		},
	}, nil
}

// publicKeyHint identifies a public key the way sigstore's
// PublicKeyIdentifier expects it: the hex-encoded SHA-256 of the
// PEM-encoded SubjectPublicKeyInfo. This is the fingerprint the
// model_signing reference implementation records and checks.
func publicKeyHint(pub *key.Public) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub.Key)
	if err != nil {
		return "", fmt.Errorf("encoding public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256(pemBytes)
	return hex.EncodeToString(sum[:]), nil
}

// chainCertificates checks a chain for the signing key and returns it as
// bundle certificates: the leaf, which must carry pub, followed by the
// intermediates, which must be CA certificates. Self-signed certificates
// after the leaf are trust anchors and are left out: verifiers trust
// them on their own terms and sigstore rejects them inside a chain.
func chainCertificates(pub *key.Public, chain []*x509.Certificate) ([]*protocommon.X509Certificate, error) {
	leaf := chain[0]
	if leaf == nil {
		return nil, errors.New("certificate chain has no leaf certificate")
	}
	if err := cryptoutils.EqualKeys(leaf.PublicKey, pub.Key); err != nil {
		return nil, fmt.Errorf("leaf certificate does not match the signing key: %w", err)
	}

	certs := []*protocommon.X509Certificate{{RawBytes: leaf.Raw}}
	for i, c := range chain[1:] {
		if c == nil {
			return nil, fmt.Errorf("certificate chain entry %d is nil", i+1)
		}
		if isSelfSigned(c) {
			continue
		}
		if !c.IsCA {
			return nil, fmt.Errorf("certificate chain entry %d (%s) is not a CA certificate", i+1, c.Subject)
		}
		certs = append(certs, &protocommon.X509Certificate{RawBytes: c.Raw})
	}
	return certs, nil
}

// isSelfSigned reports whether c signed itself.
func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}
