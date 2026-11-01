// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package signer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"

	"github.com/policylabs/signer/bundle"
	"github.com/policylabs/signer/dsse"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
)

// intotoPayloadType is the DSSE payload type of in-toto statements, the
// same for every backend.
const intotoPayloadType = "application/vnd.in-toto+json"

// Backend is one of the three signing implementations the Signer
// dispatches to. Real implementations are constructed by
// Signer.resolveBackend based on Signer.Options.Backend (or per-call
// options.WithKey overrides). A counterfeiter-generated fake lives at
// signerfakes.FakeBackend.
//
// Backends are self-contained: they hold the state they need
// (credentials, bundle/dsse signers, configured keys) and the
// per-instance caches that make repeated Sign calls cheap (one OIDC
// flow + one Fulcio cert request shared across calls).
//
//counterfeiter:generate . Backend
type Backend interface {
	// Name reports which backend this is.
	Name() options.Backend

	// SignStatement signs an in-toto attestation. Bundle backends
	// produce *BundleArtifact; the key backend produces
	// *EnvelopeArtifact.
	SignStatement(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error)

	// SignMessage signs a raw payload. Bundle backends wrap it in a
	// sigstore bundle; the key backend wraps it in a DSSE envelope
	// (caller must supply options.WithPayloadType).
	SignMessage(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error)
}

// bundleBackendBase carries the shared state and signing helpers used
// by both sigstoreBackend and spiffeBackend. Both produce sigstore
// bundles from a bundle.CredentialProvider. It is embedded by both
// the per-backend prepare logic (auto-build creds for sigstore, require
// pre-set creds for spiffe) lives on the wrapping types.
type bundleBackendBase struct {
	options      *options.Signer
	creds        bundle.CredentialProvider
	bundleSigner bundle.Signer

	// mu guards the lazy preparation state (ready, creds, bundleOpts).
	// prepare errors are not cached: ready is only set on success, so
	// later sign calls retry after a transient failure.
	mu         sync.Mutex
	ready      bool
	bundleOpts *sign.BundleOptions
}

// signBundleContent is the shared finishing step: hand the wrapped
// content to bundle.Signer.SignBundle, attach intermediates if the
// credential provider exposes any, and wrap the result for callers.
func (b *bundleBackendBase) signBundleContent(content sign.Content) (*sbundle.Bundle, error) {
	bndl, err := b.bundleSigner.SignBundle(content, b.creds.Keypair(), b.bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	if err := attachIntermediates(b.creds, bndl); err != nil {
		return nil, fmt.Errorf("attaching intermediates: %w", err)
	}
	return &sbundle.Bundle{Bundle: bndl}, nil
}

// sigstoreBackend signs through Fulcio + sigstore-go. When creds is
// nil at sign time, prepare lazily builds a sigstore.CredentialProvider
// from the configured Options.
type sigstoreBackend struct {
	bundleBackendBase
}

func newSigstoreBackend(opts *options.Signer, creds bundle.CredentialProvider, bs bundle.Signer) *sigstoreBackend {
	return &sigstoreBackend{
		bundleBackendBase: bundleBackendBase{options: opts, creds: creds, bundleSigner: bs},
	}
}

func (b *sigstoreBackend) Name() options.Backend { return options.BackendSigstore }

func (b *sigstoreBackend) SignStatement(data []byte, _ ...options.SignOptFn) (SignedArtifact, error) {
	if err := b.bundleSigner.VerifyAttestationContent(b.options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}
	if err := b.prepare(); err != nil {
		return nil, err
	}
	content := b.bundleSigner.WrapData(intotoPayloadType, data)
	bndl, err := b.signBundleContent(content)
	if err != nil {
		return nil, err
	}
	return &BundleArtifact{Bundle: bndl}, nil
}

func (b *sigstoreBackend) SignMessage(data []byte, _ ...options.SignOptFn) (SignedArtifact, error) {
	if err := b.prepare(); err != nil {
		return nil, err
	}
	content := b.bundleSigner.BuildMessage(data)
	bndl, err := b.signBundleContent(content)
	if err != nil {
		return nil, err
	}
	return &BundleArtifact{Bundle: bndl}, nil
}

// prepare builds (lazily, once) the sigstore credentials + bundle
// options. Auto-builds creds from Options when not pre-set (a
// sigstore-specific behavior). Safe for concurrent use.
func (b *sigstoreBackend) prepare() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ready {
		return nil
	}
	if b.creds == nil {
		if err := b.options.Validate(); err != nil {
			return fmt.Errorf("validating options for signing: %w", err)
		}
		b.creds = b.options.BuildSigstoreCredentials()
	}
	if err := b.creds.Prepare(context.TODO()); err != nil {
		return fmt.Errorf("preparing signing credentials: %w", err)
	}
	bo, err := b.bundleSigner.BuildBundleOptions(b.options, b.creds)
	if err != nil {
		return fmt.Errorf("building bundle options: %w", err)
	}
	b.bundleOpts = bo
	b.ready = true
	return nil
}

// spiffeBackend signs with an X.509-SVID. The credential provider must
// be supplied at construction time — this backend cannot build SPIFFE
// credentials from Options alone, so the caller has to wire up a
// *spiffe.CredentialProvider externally.
type spiffeBackend struct {
	bundleBackendBase
}

func newSpiffeBackend(opts *options.Signer, creds bundle.CredentialProvider, bs bundle.Signer) (*spiffeBackend, error) {
	if creds == nil {
		return nil, errors.New("BackendSpiffe requires Signer.Credentials to be set with a *spiffe.CredentialProvider; signer cannot build SPIFFE credentials from Options alone")
	}
	return &spiffeBackend{
		bundleBackendBase: bundleBackendBase{options: opts, creds: creds, bundleSigner: bs},
	}, nil
}

func (b *spiffeBackend) Name() options.Backend { return options.BackendSpiffe }

func (b *spiffeBackend) SignStatement(data []byte, _ ...options.SignOptFn) (SignedArtifact, error) {
	if err := b.bundleSigner.VerifyAttestationContent(b.options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}
	if err := b.prepare(); err != nil {
		return nil, err
	}
	content := b.bundleSigner.WrapData(intotoPayloadType, data)
	bndl, err := b.signBundleContent(content)
	if err != nil {
		return nil, err
	}
	return &BundleArtifact{Bundle: bndl}, nil
}

func (b *spiffeBackend) SignMessage(data []byte, _ ...options.SignOptFn) (SignedArtifact, error) {
	if err := b.prepare(); err != nil {
		return nil, err
	}
	content := b.bundleSigner.BuildMessage(data)
	bndl, err := b.signBundleContent(content)
	if err != nil {
		return nil, err
	}
	return &BundleArtifact{Bundle: bndl}, nil
}

// prepare prepares the SVID and computes bundle options. Unlike
// sigstoreBackend.prepare, this does not auto-build creds: the
// constructor enforces a non-nil creds value. Safe for concurrent use.
func (b *spiffeBackend) prepare() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ready {
		return nil
	}
	if err := b.creds.Prepare(context.TODO()); err != nil {
		return fmt.Errorf("preparing svid credentials: %w", err)
	}
	bo, err := b.bundleSigner.BuildBundleOptions(b.options, b.creds)
	if err != nil {
		return fmt.Errorf("building bundle options: %w", err)
	}
	b.bundleOpts = bo
	b.ready = true
	return nil
}

// keyBackend signs with raw private keys, producing a bare DSSE
// envelope. Two construction shapes:
//
//   - Persistent: built from Signer.Options.Keys when Backend is
//     BackendKey. keys is set; per-call options.WithKey replaces it
//     for that single call.
//   - Transient: built per call from per-call options.WithKey when the
//     persistent backend is something else. In this case keys is
//     already the per-call set.
type keyBackend struct {
	dsseSigner dsse.Signer
	keys       []key.PrivateKeyProvider
	// chain is the configured certificate chain for keys[0], used when
	// a bundle is requested and the call brings no chain of its own.
	chain []*x509.Certificate
}

func newKeyBackend(ds dsse.Signer, keys []key.PrivateKeyProvider, chain []*x509.Certificate) *keyBackend {
	return &keyBackend{dsseSigner: ds, keys: keys, chain: chain}
}

func (b *keyBackend) Name() options.Backend { return options.BackendKey }

func (b *keyBackend) SignStatement(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error) {
	return b.sign(intotoPayloadType, data, funcs...)
}

func (b *keyBackend) SignMessage(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error) {
	so := options.DefaultSign
	for _, f := range funcs {
		if err := f(&so); err != nil {
			return nil, err
		}
	}
	return b.sign(so.PayloadType, data, funcs...)
}

func (b *keyBackend) sign(payloadType string, data []byte, funcs ...options.SignOptFn) (SignedArtifact, error) {
	if payloadType == "" {
		return nil, errors.New("payload type not defined")
	}

	so := options.DefaultSign
	for _, f := range funcs {
		if err := f(&so); err != nil {
			return nil, err
		}
	}

	// Per-call options.WithKey REPLACES the configured keys for this
	// call. When the per-call set is empty, fall back to the
	// configured keys.
	keys := so.Keys
	if len(keys) == 0 {
		keys = b.keys
	}
	if len(keys) == 0 {
		return nil, errors.New("no signing keys; pass options.WithKey(...) or set Signer.Options.Backend=BackendKey + Signer.Options.Keys")
	}

	// A per-call chain replaces the configured one, like keys do. The
	// configured chain only applies to the configured keys.
	chain := so.CertificateChain
	if len(chain) == 0 && len(so.Keys) == 0 {
		chain = b.chain
	}
	wantBundle := so.Bundle || len(chain) > 0

	// Check the bundle material before signing, so a bad chain is
	// reported without doing the work.
	var material *protobundle.VerificationMaterial
	if wantBundle {
		var err error
		material, err = keyVerificationMaterial(keys[0], chain)
		if err != nil {
			return nil, err
		}
	}

	env, err := b.dsseSigner.WrapPayload(payloadType, data)
	if err != nil {
		return nil, fmt.Errorf("wrapping payload: %w", err)
	}
	if err := b.dsseSigner.Sign(env, keys); err != nil {
		return nil, fmt.Errorf("signing envelope: %w", err)
	}
	if !wantBundle {
		return &EnvelopeArtifact{Envelope: env}, nil
	}
	return &BundleArtifact{Bundle: bundleFromEnvelope(env, material)}, nil
}

// attachIntermediates rewrites the bundle's VerificationMaterial to
// carry [leaf, ...intermediates] when the credential provider exposes
// intermediates. Called after SignBundle so the leaf DER is already
// present in VerificationMaterial.Content. When the provider returns
// an empty chain (the sigstore case) the bundle is left untouched.
func attachIntermediates(creds bundle.CredentialProvider, bndl *protobundle.Bundle) error {
	if creds == nil {
		return nil
	}
	ints := creds.Intermediates()
	if len(ints) == 0 {
		return nil
	}
	if bndl.GetVerificationMaterial() == nil {
		return errors.New("bundle has no verification material")
	}
	leaf, ok := bndl.GetVerificationMaterial().GetContent().(*protobundle.VerificationMaterial_Certificate)
	if !ok || leaf.Certificate == nil {
		// Already a chain, a public key, or nothing — leave as-is.
		return nil
	}

	chain := &protocommon.X509CertificateChain{
		Certificates: make([]*protocommon.X509Certificate, 0, 1+len(ints)),
	}
	chain.Certificates = append(chain.Certificates, &protocommon.X509Certificate{
		RawBytes: leaf.Certificate.GetRawBytes(),
	})
	for _, c := range ints {
		chain.Certificates = append(chain.Certificates, &protocommon.X509Certificate{
			RawBytes: c.Raw,
		})
	}
	bndl.VerificationMaterial.Content = &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: chain,
	}
	// sigstore-go's sbundle.NewBundle rejects X509CertificateChain
	// content at v0.3 (only single Certificate allowed). v0.2 permits
	// the chain variant, which is exactly what SPIFFE signing needs to
	// carry intermediates.
	bndl.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.2"
	return nil
}
