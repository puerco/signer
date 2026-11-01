// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeSelfSignedPEM writes a self-signed certificate to dir and returns
// its path. count certificates are concatenated when asked.
func writeSelfSignedPEM(t *testing.T, dir, name string, count int) string {
	t.Helper()
	var out []byte
	for i := range count {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		require.NoError(t, err)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path := filepath.Join(dir, name+".pem")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

// The signing certificate file must hold one certificate; chain files may
// hold several, and the chain cannot be given without the certificate.
func TestKeysSignCertificateChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	leaf := writeSelfSignedPEM(t, dir, "leaf", 1)
	chain := writeSelfSignedPEM(t, dir, "chain", 2)
	two := writeSelfSignedPEM(t, dir, "two", 2)

	k := DefaultKeysSign()
	certs, err := k.ParseCertificateChain()
	require.NoError(t, err)
	require.Nil(t, certs)

	k.CertificatePath = leaf
	k.CertificateChainPaths = []string{chain}
	require.NoError(t, k.Validate())
	certs, err = k.ParseCertificateChain()
	require.NoError(t, err)
	require.Len(t, certs, 3)
	require.Equal(t, "leaf", certs[0].Subject.CommonName)

	k.CertificatePath = two
	_, err = k.ParseCertificateChain()
	require.ErrorContains(t, err, "exactly one certificate")

	k.CertificatePath = ""
	require.ErrorContains(t, k.Validate(), "requires --signing-cert")

	k.CertificatePath = filepath.Join(dir, "missing.pem")
	require.ErrorContains(t, k.Validate(), "checking signing certificate")
}
