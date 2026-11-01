// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/dsse"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

const keyBundleStatement = `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicateType":"https://example.com/t","predicate":{}}`

// keySigner returns a signer that can only sign with keys.
func keySigner() *Signer {
	return &Signer{dsseSigner: dsse.NewSigner()}
}

func generateKey(t *testing.T, curve elliptic.Curve) *key.Private {
	t.Helper()
	k, err := key.NewGenerator().GenerateKeyPair(key.WithEllipticCurve(curve))
	require.NoError(t, err)
	return k
}

// expectedHint computes the hint the way the model_signing reference
// does: sha256 over the PEM SubjectPublicKeyInfo.
func expectedHint(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	sum := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return hex.EncodeToString(sum[:])
}

// roundTrip serializes the artifact and parses it back through the
// signer's own parser, the way a consumer would read it from disk.
func roundTrip(t *testing.T, art SignedArtifact) *sbundle.Bundle {
	t.Helper()
	var buf bytes.Buffer
	_, err := art.WriteTo(&buf)
	require.NoError(t, err)
	parsed, err := ParseArtifact(buf.Bytes())
	require.NoError(t, err)
	ba, ok := parsed.(*BundleArtifact)
	require.True(t, ok, "expected a bundle artifact, got %T", parsed)
	return ba.Bundle
}

// A key signs into a bundle when asked. The bundle identifies the key by
// the hint the model_signing reference uses, carries the DSSE envelope,
// parses back through sigstore-go and verifies with the public key.
func TestKeyBackendBundle(t *testing.T) {
	t.Parallel()
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			k := generateKey(t, curve)
			pub, err := k.PublicKey()
			require.NoError(t, err)

			art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(k), options.WithBundle())
			require.NoError(t, err)
			require.Equal(t, ArtifactKindBundle, art.Kind())
			require.Equal(t, keyBundleMediaType, art.MediaType())

			b := roundTrip(t, art)
			vm := b.GetVerificationMaterial()
			require.Equal(t, expectedHint(t, pub.Key), vm.GetPublicKey().GetHint())
			require.Empty(t, vm.GetTlogEntries())
			env := b.GetDsseEnvelope()
			require.NotNil(t, env)
			require.Equal(t, "https://in-toto.io/Statement/v1", env.GetPayloadType())
			require.Len(t, env.GetSignatures(), 1)

			vc, err := b.VerificationContent()
			require.NoError(t, err)
			require.IsType(t, &sbundle.PublicKey{}, vc)

			res, err := NewVerifier().VerifyParsedDSSE(env, []key.PublicKeyProvider{pub})
			require.NoError(t, err)
			require.True(t, res.Verified)
		})
	}
}

// Without the option the key backend keeps answering with an envelope,
// and SignStatementBundle now serves the key backend too.
func TestKeyBackendEnvelopeByDefault(t *testing.T) {
	t.Parallel()
	k := generateKey(t, elliptic.P256())

	art, err := keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(k))
	require.NoError(t, err)
	require.Equal(t, ArtifactKindEnvelope, art.Kind())

	s := keySigner()
	s.Options.Backend = options.BackendKey
	s.Options.Keys = []key.PrivateKeyProvider{k}
	b, err := s.SignStatementBundle([]byte(keyBundleStatement))
	require.NoError(t, err)
	require.NotEmpty(t, b.GetVerificationMaterial().GetPublicKey().GetHint())

	m, err := s.SignMessageBundle([]byte("hello"), options.WithPayloadType("text/plain"))
	require.NoError(t, err)
	require.Equal(t, "text/plain", m.GetDsseEnvelope().GetPayloadType())
}

// testPKI is a root CA, an intermediate and a leaf certificate issued
// to the signing key.
type testPKI struct {
	root, intermediate, leaf *x509.Certificate
}

func newTestPKI(t *testing.T, leafKey crypto.PublicKey) testPKI {
	t.Helper()
	newCA := func(name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, priv
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, priv
	}
	root, rootKey := newCA("root", nil, nil)
	intermediate, intKey := newCA("intermediate", root, rootKey)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, intermediate, leafKey, intKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testPKI{root: root, intermediate: intermediate, leaf: leaf}
}

// With a certificate chain the bundle carries the leaf and the
// intermediates, leaving the root out, at bundle v0.3, and parses back
// as certificate verification content.
func TestKeyBackendCertificateChain(t *testing.T) {
	t.Parallel()
	k := generateKey(t, elliptic.P256())
	pub, err := k.PublicKey()
	require.NoError(t, err)
	pki := newTestPKI(t, pub.Key)

	art, err := keySigner().SignStatement(
		[]byte(keyBundleStatement),
		options.WithKey(k), options.WithCertificateChain(pki.leaf, pki.intermediate, pki.root),
	)
	require.NoError(t, err)
	require.Equal(t, keyBundleMediaType, art.MediaType())

	b := roundTrip(t, art)
	certs := b.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	require.Len(t, certs, 2, "the self-signed root must not be in the chain")
	require.Equal(t, pki.leaf.Raw, certs[0].GetRawBytes())
	require.Equal(t, pki.intermediate.Raw, certs[1].GetRawBytes())

	vc, err := b.VerificationContent()
	require.NoError(t, err)
	require.IsType(t, &sbundle.Certificate{}, vc)

	// The configured chain on the signer options works the same way.
	s := keySigner()
	s.Options.Backend = options.BackendKey
	s.Options.Keys = []key.PrivateKeyProvider{k}
	s.Options.CertificateChain = []*x509.Certificate{pki.leaf, pki.intermediate}
	bndl, err := s.SignStatementBundle([]byte(keyBundleStatement))
	require.NoError(t, err)
	require.Len(t, bndl.GetVerificationMaterial().GetX509CertificateChain().GetCertificates(), 2)

	// Per-call keys do not pick up the configured chain.
	other := generateKey(t, elliptic.P256())
	bndl, err = s.SignStatementBundle([]byte(keyBundleStatement), options.WithKey(other))
	require.NoError(t, err)
	require.NotEmpty(t, bndl.GetVerificationMaterial().GetPublicKey().GetHint())
}

// A chain that does not belong to the signing key, or that holds a
// non-CA intermediate, is refused before anything is signed.
func TestKeyBackendCertificateChainErrors(t *testing.T) {
	t.Parallel()
	k := generateKey(t, elliptic.P256())
	pub, err := k.PublicKey()
	require.NoError(t, err)
	pki := newTestPKI(t, pub.Key)

	other := generateKey(t, elliptic.P256())
	_, err = keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(other), options.WithCertificateChain(pki.leaf))
	require.ErrorContains(t, err, "does not match the signing key")

	_, err = keySigner().SignStatement([]byte(keyBundleStatement), options.WithKey(k), options.WithCertificateChain(pki.leaf, pki.leaf))
	require.ErrorContains(t, err, "not a CA certificate")
}
