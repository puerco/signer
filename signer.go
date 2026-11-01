// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/signer/bundle"
	"github.com/policylabs/signer/dsse"
	"github.com/policylabs/signer/options"
	"github.com/policylabs/signer/sigstore"
)

// NewSignerFromSet builds a fully-armed *Signer from a SignerSet.
// Equivalent to: BuildSigner + BuildCredentialProvider + NewSigner +
// field assignment, in one call. Lives in this package (not options/)
// because options/ cannot import signer/ — see the package-level
// comments on SignerSet for the import-cycle reasoning.
//
// The caller is responsible for closing the returned Signer when done
// (via Signer.Close) so any Workload API stream lazily opened by the
// SPIFFE backend is released.
func NewSignerFromSet(set *options.SignerSet) (*Signer, error) {
	if set == nil {
		return nil, errors.New("NewSignerFromSet: set is nil")
	}
	opts, err := set.BuildSigner()
	if err != nil {
		return nil, err
	}
	creds, err := set.BuildCredentialProvider()
	if err != nil {
		return nil, err
	}
	s := NewSigner()
	s.Options = *opts
	if creds != nil {
		s.Credentials = creds
	}
	return s, nil
}

// NewSigner creates a new signer and initializes it with the default sigstore
// roots embedded in the package.
func NewSigner() *Signer {
	// Parse the default roots, by default we sign using the first sigstore
	// root which is tested to ensure it is sign-capable
	opts := options.DefaultSigner
	roots, err := sigstore.ParseRoots(opts.SigstoreRootsData)
	if err == nil && len(roots.Roots) > 0 {
		opts.Instance = roots.Roots[0].Instance
	} else {
		// This is a fatal err. This should never happen as the package embeds
		// the roots information and we have unit tests to check they are valid
		// but we rather fail here instead of leaving apps to do something funky
		// with the signer if for some reason the roots data is invalid.
		errm := ""
		if err != nil {
			errm = fmt.Sprintf(" (%s)", err.Error())
		} else if len(roots.Roots) == 0 {
			errm = " (no roots defined)"
		}
		logrus.Fatalf("failed parsing roots config%s", errm)
	}
	return &Signer{
		Options:      opts,
		bundleSigner: bundle.NewSigner(),
		dsseSigner:   dsse.NewSigner(),
	}
}

// Signer is a thin orchestrator. It owns the configuration
// (Options + Credentials + bundle/dsse signers) and resolves the
// concrete Backend that does the actual signing on each call. The
// signing logic lives entirely in the Backend implementations
// (sigstoreBackend / spiffeBackend / keyBackend in backend.go).
//
// A Signer instance is safe for concurrent use by multiple goroutines
// once constructed: the lazy backend/credential initialization and the
// Fulcio certificate cache are internally synchronized.
//
// Important: Options and Credentials must not be mutated after the
// first sign call.
type Signer struct {
	Options options.Signer

	// Credentials supplies the keypair and certificate material for the
	// bundle backends (sigstore / SPIFFE). Pre-set for SPIFFE; for
	// sigstore the backend will lazily build a sigstore.CredentialProvider
	// from Options if this is nil.
	//
	// The Signer carries no per-instance signing-key state. To sign with
	// raw private keys, either configure Options.Backend = BackendKey +
	// Options.Keys, or pass options.WithKey(...) at the call site.
	Credentials bundle.CredentialProvider

	bundleSigner bundle.Signer
	dsseSigner   dsse.Signer

	// persistent caches the resolved Backend across calls so the OIDC
	// flow + Fulcio cert request happen once, not per call. Built
	// lazily on first sign call under mu. Per-call options.WithKey
	// produces a transient keyBackend that does NOT replace this cache.
	persistent Backend

	// mu guards the lazy construction of persistent.
	mu sync.Mutex
}

// SignStatement signs an in-toto attestation and returns a polymorphic
// SignedArtifact. Resolution rules:
//
//  1. Per-call options.WithKey(...) → transient key backend using the
//     per-call keys (Signer.Options.Keys ignored for this invocation).
//  2. Otherwise the persistent backend (lazily built from
//     Signer.Options.Backend on first call) signs:
//     BackendSigstore (default) / BackendSpiffe → *BundleArtifact;
//     BackendKey → *EnvelopeArtifact signed with Signer.Options.Keys.
//
// Errors out before signing when the resolved backend's configuration
// is incomplete (e.g. BackendKey selected but no keys available).
func (s *Signer) SignStatement(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error) {
	backend, err := s.resolveBackend(funcs)
	if err != nil {
		return nil, err
	}
	return backend.SignStatement(data, funcs...)
}

// SignMessage signs a payload and returns a polymorphic SignedArtifact.
// Backend resolution follows the same rules as SignStatement. The DSSE
// path requires options.WithPayloadType.
func (s *Signer) SignMessage(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error) {
	backend, err := s.resolveBackend(funcs)
	if err != nil {
		return nil, err
	}
	return backend.SignMessage(data, funcs...)
}

// resolveBackend selects the right Backend for a polymorphic Sign call.
// Per-call options.WithKey forces a transient keyBackend; otherwise
// the persistent backend (lazy, cached) is returned.
func (s *Signer) resolveBackend(funcs []options.SignOptFn) (Backend, error) {
	so := options.DefaultSign
	for _, f := range funcs {
		if err := f(&so); err != nil {
			return nil, err
		}
	}
	if len(so.Keys) > 0 {
		return newKeyBackend(s.dsseSigner, so.Keys, nil), nil
	}
	return s.persistentBackend()
}

// persistentBackend returns the cached persistent backend, building it
// on first call from Signer.Options.Backend. Safe for concurrent use;
// construction errors are not cached, so later calls retry.
func (s *Signer) persistentBackend() (Backend, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.persistent != nil {
		return s.persistent, nil
	}

	backend := s.Options.Backend
	if backend == "" {
		backend = options.BackendSigstore
	}

	switch backend {
	case options.BackendSigstore:
		s.persistent = newSigstoreBackend(&s.Options, s.Credentials, s.bundleSigner)
		return s.persistent, nil

	case options.BackendSpiffe:
		b, err := newSpiffeBackend(&s.Options, s.Credentials, s.bundleSigner)
		if err != nil {
			return nil, err
		}
		s.persistent = b
		return s.persistent, nil

	case options.BackendKey:
		if len(s.Options.Keys) == 0 {
			return nil, errors.New("Signer.Options.Backend is BackendKey but Signer.Options.Keys is empty; configure keys or pass options.WithKey(...) per call")
		}
		s.persistent = newKeyBackend(s.dsseSigner, s.Options.Keys, s.Options.CertificateChain)
		return s.persistent, nil

	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
}

// SignStatementBundle signs an in-toto attestation and returns a
// sigstore bundle. Resolves the persistent backend and unwraps its
// artifact. The key backend is asked for a bundle (see
// options.WithBundle), so every backend answers with one.
//
// Use the polymorphic SignStatement when you want format-agnostic
// dispatch.
func (s *Signer) SignStatementBundle(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
	backend, err := s.persistentBackend()
	if err != nil {
		return nil, err
	}
	if backend.Name() == options.BackendKey {
		funcs = append(append([]options.SignOptFn{}, funcs...), options.WithBundle())
	}
	art, err := backend.SignStatement(data, funcs...)
	if err != nil {
		return nil, err
	}
	ba, ok := art.(*BundleArtifact)
	if !ok || ba == nil {
		return nil, fmt.Errorf("backend %q produced a non-bundle artifact (%T)", backend.Name(), art)
	}
	return ba.Bundle, nil
}

// SignMessageBundle signs a payload and returns a sigstore bundle.
// Same dispatch rules as SignStatementBundle.
func (s *Signer) SignMessageBundle(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
	backend, err := s.persistentBackend()
	if err != nil {
		return nil, err
	}
	if backend.Name() == options.BackendKey {
		funcs = append(append([]options.SignOptFn{}, funcs...), options.WithBundle())
	}
	art, err := backend.SignMessage(data, funcs...)
	if err != nil {
		return nil, err
	}
	ba, ok := art.(*BundleArtifact)
	if !ok || ba == nil {
		return nil, fmt.Errorf("backend %q produced a non-bundle artifact (%T)", backend.Name(), art)
	}
	return ba.Bundle, nil
}

// SignStatementToDSSE signs an in-toto statement as a bare DSSE
// envelope. Constructs a transient keyBackend from per-call keys (or
// Signer.Options.Keys when Backend=BackendKey). Errors when no keys
// are available.
func (s *Signer) SignStatementToDSSE(data []byte, funcs ...options.SignOptFn) (*sdsse.Envelope, error) {
	funcs = append([]options.SignOptFn{}, funcs...)
	funcs = append(funcs, options.WithPayloadType(intotoPayloadType))
	return s.SignMessageToDSSE(data, funcs...)
}

// SignMessageToDSSE signs a payload as a bare DSSE envelope. Requires
// keys from per-call options.WithKey or Signer.Options.Keys (when
// Backend=BackendKey).
func (s *Signer) SignMessageToDSSE(data []byte, funcs ...options.SignOptFn) (*sdsse.Envelope, error) {
	so := options.DefaultSign
	for _, f := range funcs {
		if err := f(&so); err != nil {
			return nil, err
		}
	}

	keys := so.Keys
	if len(keys) == 0 && s.Options.Backend == options.BackendKey {
		keys = s.Options.Keys
	}
	if len(keys) == 0 {
		return nil, errors.New("no signing keys; pass options.WithKey(...) or set Signer.Options.Backend=BackendKey + Signer.Options.Keys")
	}

	backend := newKeyBackend(s.dsseSigner, keys, nil)
	art, err := backend.SignMessage(data, funcs...)
	if err != nil {
		return nil, err
	}
	ea, ok := art.(*EnvelopeArtifact)
	if !ok || ea == nil {
		return nil, fmt.Errorf("key backend produced a non-envelope artifact (%T)", art)
	}
	return ea.Envelope, nil
}

// SignEnvelope signs an existing DSSE envelope. Key resolution mirrors
// the polymorphic Sign methods:
//
//   - Per-call options.WithKey(...) wins → those keys sign this
//     envelope (the configured backend is disregarded for this call).
//   - Otherwise, if Signer.Options.Backend == BackendKey, the
//     configured Signer.Options.Keys are used.
//   - Otherwise → error. Sigstore/SPIFFE backends produce bundles
//     end-to-end; they don't sign pre-existing standalone envelopes.
func (s *Signer) SignEnvelope(envelope *sdsse.Envelope, funcs ...options.SignOptFn) error {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return err
		}
	}

	keys := signOpts.Keys
	if len(keys) == 0 && s.Options.Backend == options.BackendKey {
		keys = s.Options.Keys
	}
	if len(keys) == 0 {
		return errors.New("no signing keys; configure Signer.Options.Backend=BackendKey + Signer.Options.Keys, or pass options.WithKey(...) per call")
	}

	if err := s.dsseSigner.Sign(envelope, keys); err != nil {
		return fmt.Errorf("signing envelope: %w", err)
	}
	return nil
}

// CertifiedKey runs the keyless (Fulcio) flow with a fresh key and returns the
// leaf certificate, its intermediate chain, and the private key, suitable for
// building a detached CMS/PKCS7 signature. It uses the same ambient identity
// as the signer's sigstore backend: the OIDC token is obtained through the
// existing credential/Prepare flow, honoring an injected Options.Token and DisableSTS.
//
// It requires the sigstore backend. When Signer.Credentials is already a
// *sigstore.CredentialProvider it is reused, otherwise one is built from
// Signer.Options. A non-sigstore Credentials value is rejected.
func (s *Signer) CertifiedKey(ctx context.Context) (leaf *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, err error) {
	var cp *sigstore.CredentialProvider
	switch creds := s.Credentials.(type) {
	case nil:
		if verr := s.Options.Validate(); verr != nil {
			return nil, nil, nil, fmt.Errorf("validating options: %w", verr)
		}
		cp = s.Options.BuildSigstoreCredentials()
	case *sigstore.CredentialProvider:
		cp = creds
	default:
		return nil, nil, nil, fmt.Errorf("CertifiedKey requires the sigstore backend; Signer.Credentials is %T", s.Credentials)
	}
	return cp.CertifiedKey(ctx)
}

// Close releases resources held by the Signer's credentials. It's a
// no-op when Credentials is nil or doesn't hold any closeable
// resources; today only the SPIFFE credential provider has anything
// to release (the Workload API stream lazily opened on first sign).
// Safe to call multiple times.
func (s *Signer) Close() error {
	if s == nil || s.Credentials == nil {
		return nil
	}
	if c, ok := s.Credentials.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// WriteBundle marshals a sigstore bundle to JSON and writes it to w.
func (s *Signer) WriteBundle(bndl *sbundle.Bundle, w io.Writer) error {
	bundleJSON, err := protojson.Marshal(bndl)
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}
	if _, err := w.Write(bundleJSON); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}
	return nil
}

// WriteDSSEEnvelope marshals a DSSE envelope to JSON and writes it to
// an io.Writer.
func (s *Signer) WriteDSSEEnvelope(env *sdsse.Envelope, w io.Writer) error {
	marshaler := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	data, err := marshaler.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing data to writer sink: %w", err)
	}
	return nil
}
