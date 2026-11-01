// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/x509"

	"github.com/policylabs/signer/key"
)

// Sign options (not to be confused with signer options) are options
// that control each signing operation behavior.
type Sign struct {
	// PayloadType is the payload type to be declared in DSSE envelopes
	PayloadType string

	// PrivateKeys for DSSE envelope signing. These will be honored later
	// to reuse in bundle signing
	Keys []key.PrivateKeyProvider

	// Bundle asks the key backend to wrap the signed DSSE envelope in a
	// sigstore bundle instead of returning the bare envelope. The
	// bundle's verification material identifies the signing key by a
	// hint (the hex SHA-256 of its PEM-encoded public key) unless a
	// certificate chain is given. The sigstore and SPIFFE backends
	// always produce bundles, so they ignore this option.
	Bundle bool

	// CertificateChain is the certificate issued to the signing key
	// followed by its intermediates. When set, the key backend produces
	// a bundle (Bundle is implied) whose verification material carries
	// the chain instead of a key hint. Self-signed certificates after
	// the leaf (trust anchors) are dropped, since verifiers hold those
	// already and sigstore refuses them inside a chain.
	CertificateChain []*x509.Certificate
}

var DefaultSign = Sign{
	PayloadType: "application/octet-stream",
}

type SignOptFn = func(*Sign) error

// WithPayloadType sets the DSSE payload type
func WithPayloadType(t string) SignOptFn {
	return func(opts *Sign) error {
		opts.PayloadType = t
		return nil
	}
}

// WithKey adds one or more key providers that will be used to sign
func WithKey(keys ...key.PrivateKeyProvider) SignOptFn {
	return func(opts *Sign) error {
		opts.Keys = append(opts.Keys, keys...)
		return nil
	}
}

// WithBundle makes the key backend return a sigstore bundle instead of
// a bare DSSE envelope. See Sign.Bundle.
func WithBundle() SignOptFn {
	return func(opts *Sign) error {
		opts.Bundle = true
		return nil
	}
}

// WithCertificateChain records the certificate issued to the signing
// key, and its intermediates, in the bundle the key backend produces.
// See Sign.CertificateChain.
func WithCertificateChain(leaf *x509.Certificate, intermediates ...*x509.Certificate) SignOptFn {
	return func(opts *Sign) error {
		opts.Bundle = true
		opts.CertificateChain = append([]*x509.Certificate{leaf}, intermediates...)
		return nil
	}
}
