// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/sigstore"
)

// Backend selects which signing backend the Signer uses. Three
// independent implementations:
//
//   - BackendSigstore: a Fulcio-issued cert + DSSE + optional
//     Rekor/TSA, produced as a sigstore bundle. signingState
//     auto-builds a sigstore.CredentialProvider from this Options
//     struct on first use when Signer.Credentials is nil.
//   - BackendSpiffe: an X.509-SVID + DSSE produced as a sigstore
//     bundle, including the SPIRE upstream intermediates. Requires
//     Signer.Credentials to be pre-populated with a
//     *spiffe.CredentialProvider — signingState cannot build SPIFFE
//     credentials from Options alone.
//   - BackendKey: raw private-key signing producing a bare DSSE
//     envelope (no cert chain, no Rekor, no TSA). Uses Signer.Options.Keys.
//
// At the polymorphic layer (Signer.SignStatement / Signer.SignMessage),
// Sigstore and Spiffe both yield *BundleArtifact; Key yields
// *EnvelopeArtifact.
//
// Specialized methods on Signer behave as follows w.r.t. this field:
//
//   - SignStatementBundle / SignMessageBundle work for either bundle
//     backend (Sigstore or Spiffe) — they read Backend via
//     signingState to know which CredentialProvider to use, and error
//     if Backend is Key.
//   - SignStatementToDSSE / SignMessageToDSSE work regardless of
//     Backend; they only need keys (via per-call options.WithKey or
//     Signer.Options.Keys).
type Backend string

const (
	// BackendSigstore signs through Fulcio + sigstore-go.
	// Default when Backend is left unset.
	BackendSigstore Backend = "sigstore"

	// BackendKey signs against raw private keys held in Signer.Keys,
	// producing a bare DSSE envelope.
	BackendKey Backend = "key"

	// BackendSpiffe signs with an X.509-SVID from the SPIFFE Workload
	// API. The signer.Signer's Credentials must be set to a
	// *spiffe.CredentialProvider — the runtime cannot yet build SPIFFE
	// credentials from Options alone.
	BackendSpiffe Backend = "spiffe"
)

var DefaultSigner = Signer{
	SigstoreRootsData: sigstore.DefaultRoots, // Embedded data from the rootsfile
}

// Signer is the stateful sign-side configuration for the top-level
// signer.Signer. It selects the backend and carries the material that
// backend needs.
type Signer struct {
	Sigstore
	Token             *oauthflow.OIDCIDToken
	SigstoreRootsData []byte

	// Backend selects which signing path the polymorphic Sign methods
	// take. Empty defaults to BackendBundle.
	Backend Backend

	// Keys are the private keys the key backend will sign with. Only
	// consulted when Backend == BackendKey AND no per-call
	// options.WithKey(...) is supplied. Per-call WithKey replaces (does
	// not augment) these keys for the single invocation that passes it.
	Keys []key.PrivateKeyProvider

	// CertificateChain is the certificate issued to the first of Keys,
	// followed by its intermediates. When set, bundles produced by the
	// key backend carry the chain as their verification material
	// instead of a key hint. Per-call options.WithCertificateChain
	// replaces it for that invocation.
	CertificateChain []*x509.Certificate

	parsedRoots bool
}

// ParseRoots parses the root information and assigns the instance data in
// the sigstore options
func (so *Signer) ParseRoots() error {
	if so.parsedRoots {
		return nil
	}
	roots, err := sigstore.ParseRoots(so.SigstoreRootsData)
	if err != nil {
		return fmt.Errorf("invalid root data: %w", err)
	}

	if len(roots.Roots) == 0 {
		return fmt.Errorf("no root configuration found")
	}

	so.Instance = roots.Roots[0].Instance
	so.parsedRoots = true
	return nil
}

// Validate checks the signer options
func (so *Signer) Validate() error {
	if err := so.ParseRoots(); err != nil {
		return fmt.Errorf("parsing roots: %w", err)
	}

	errs := []error{
		so.ValidateSigner(),
	}
	return errors.Join(errs...)
}

// BuildSigstoreCredentials constructs a sigstore.CredentialProvider from the
// options, forwarding the DisableSTS flag and any pre-provided OIDC token.
// Used by the outer Signer to default-construct a provider when none was
// injected.
func (so *Signer) BuildSigstoreCredentials() *sigstore.CredentialProvider {
	cp := sigstore.NewCredentialProvider(&so.Instance)
	cp.DisableSTS = so.DisableSTS
	cp.Token = so.Token
	return cp
}
