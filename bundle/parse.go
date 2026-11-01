// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

// ParseJSON parses a sigstore bundle from its JSON form. Unlike
// sigstore-go's own UnmarshalJSON it accepts a certificate chain as
// verification material at bundle v0.3, which is what key-signed
// bundles with a chain, SPIFFE bundles and the OpenSSF Model Signing
// bundles carry.
func ParseJSON(data []byte) (*bundle.Bundle, error) {
	pb := &protobundle.Bundle{}
	if err := protojson.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}
	b, err := bundle.NewBundle(pb, bundle.AllowCertificateChain())
	if err != nil {
		return nil, fmt.Errorf("validating bundle: %w", err)
	}
	return b, nil
}

// ParseFile reads a bundle file and parses it with ParseJSON.
func ParseFile(path string) (*bundle.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle: %w", err)
	}
	return ParseJSON(data)
}
