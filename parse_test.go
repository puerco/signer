// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"os"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/signer/bundle"
)

// The signer's parsers accept the bundles published as OpenSSF Model
// Signing test vectors, including the certificate one, which carries a
// chain at bundle v0.3 and sigstore-go rejects without the chain option.
func TestParseOMSBundles(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file  string
		chain bool
	}{
		{"testdata/oms-key.bundle.json", false},
		{"testdata/oms-certificate.bundle.json", true},
	} {
		data, err := os.ReadFile(tc.file)
		require.NoError(t, err)

		art, err := ParseArtifact(data)
		require.NoError(t, err, tc.file)
		ba, ok := art.(*BundleArtifact)
		require.True(t, ok)

		b, err := bundle.ParseJSON(data)
		require.NoError(t, err, tc.file)
		if tc.chain {
			require.NotEmpty(t, b.GetVerificationMaterial().GetX509CertificateChain().GetCertificates())
			require.IsType(t, &protobundle.VerificationMaterial_X509CertificateChain{}, ba.Bundle.GetVerificationMaterial().GetContent())
		} else {
			require.NotEmpty(t, b.GetVerificationMaterial().GetPublicKey().GetHint())
		}
		_, err = b.VerificationContent()
		require.NoError(t, err, tc.file)
	}
}
