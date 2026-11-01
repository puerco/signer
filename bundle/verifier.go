// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/nozzle/throttler"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"

	api "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/options"
	"github.com/policylabs/signer/sigstore"
)

type BundleOptsFunc func(*DefaultVerifier) error

// WithSigstoreRootsData sets the raw json data holding the sigstore instances
// configuration
func WithSigstoreRootsData(data []byte) BundleOptsFunc {
	return func(v *DefaultVerifier) error {
		roots, err := sigstore.ParseRoots(data)
		if err != nil {
			return err
		}

		// Verifiers are built on first use, not here. Building one
		// resolves the instance's trusted root, which can go to TUF over
		// the network, and a verifier that only ever checks key or SPIFFE
		// signatures must never pay for that.
		for i := range roots.Roots {
			v.Verifiers = append(v.Verifiers, &lazyVerifier{
				conf:  &roots.Roots[i],
				build: v.BuildSigstoreVerifier,
			})
		}
		return nil
	}
}

// lazyVerifier defers building the sigstore verifier for an instance until
// a bundle is actually verified against it. The build runs once; its
// result (or error) is reused by every later verification.
type lazyVerifier struct {
	conf  *sigstore.InstanceConfig
	build func(*sigstore.InstanceConfig) (VerifyCapable, error)

	once     sync.Once
	verifier VerifyCapable
	err      error
}

// resolve returns the built verifier, building it on the first call.
func (l *lazyVerifier) resolve() (VerifyCapable, error) {
	l.once.Do(func() {
		l.verifier, l.err = l.build(l.conf)
	})
	if l.err != nil {
		return nil, fmt.Errorf("building verifier for sigstore instance %q: %w", l.conf.ID, l.err)
	}
	return l.verifier, nil
}

// Verify builds the underlying verifier if needed and delegates to it.
func (l *lazyVerifier) Verify(entity verify.SignedEntity, policy verify.PolicyBuilder) (*verify.VerificationResult, error) {
	v, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return v.Verify(entity, policy)
}

// WithSpiffeVerifier installs the verifier used when a bundle carries a
// SPIFFE-shaped identity (leaf cert with a spiffe:// URI SAN).
func WithSpiffeVerifier(sv SpiffeVerifier) BundleOptsFunc {
	return func(v *DefaultVerifier) error {
		v.SPIFFE = sv
		return nil
	}
}

// New creates a new verifier. Initialization errors are logged to stderr
// but not returned. Use NewWithError if you need to handle errors.
func New(funcs ...BundleOptsFunc) Verifier {
	v, err := NewWithError(funcs...)
	if err != nil {
		log.Default().Print(err)
	}
	return v
}

// NewWithError creates a new verifier and returns any initialization error.
func NewWithError(funcs ...BundleOptsFunc) (Verifier, error) {
	ret := &DefaultVerifier{}
	for _, f := range funcs {
		if err := f(ret); err != nil {
			return ret, err
		}
	}

	return ret, nil
}

// VerifyCapable abstracts the verifier to mock
type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

// SpiffeVerifier verifies bundles signed against a SPIFFE/SPIRE trust domain.
// Implemented by spiffe.Verifier; typed as an interface here so the bundle
// package doesn't have to import the spiffe package.
type SpiffeVerifier interface {
	Verify(*options.Verification, *bundle.Bundle) (*verify.VerificationResult, error)
}

// BundleVerifier abstracts the verification implementation to make it easy to
// mock for testing.
//
//counterfeiter:generate . Verifier
type Verifier interface {
	Verify(*options.Verification, *bundle.Bundle) (*verify.VerificationResult, error)
	OpenBundle(string) (*bundle.Bundle, error)
	BuildSigstoreVerifier(*sigstore.InstanceConfig) (VerifyCapable, error)
	RunVerification(*options.SigstoreVerification, VerifyCapable, *bundle.Bundle) (*verify.VerificationResult, error)
}

// DefaultVerifier implements the BundleVerifier interface.
type DefaultVerifier struct {
	Verifiers []VerifyCapable

	// SPIFFE, when set, handles bundles whose leaf certificate carries a
	// spiffe:// URI SAN. Constructed outside this package (typically in
	// signer.NewVerifier) to avoid a bundle -> spiffe import dependency.
	SPIFFE SpiffeVerifier
}

// OpenBundle opens a bundle file
func (bv *DefaultVerifier) OpenBundle(path string) (*bundle.Bundle, error) {
	b, err := ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening path: %w", err)
	}
	return b, nil
}

// Verify is the main verification function to check bundles. Dispatches to
// the SPIFFE verifier when the bundle carries a spiffe:// URI SAN; otherwise
// iterates the configured sigstore instances.
//
// Errors carry the verification conclusion: api.ErrUnverifiable when no
// verifier is configured for the bundle's kind, api.ErrVerificationFailed
// when every applicable instance concluded the bundle does not verify. An
// error wrapping neither means nothing was concluded: at least one
// instance could not run the verification, so the bundle may still be
// valid against it.
func (bv *DefaultVerifier) Verify(opts *options.Verification, bndl *bundle.Bundle) (*verify.VerificationResult, error) {
	if isSpiffeBundle(bndl) {
		if bv.SPIFFE == nil {
			return nil, api.UnverifiableError("bundle carries a spiffe identity but no spiffe verifier is configured", nil)
		}
		return bv.SPIFFE.Verify(opts, bndl)
	}
	if len(bv.Verifiers) == 0 {
		return nil, api.UnverifiableError("no sigstore instances loaded", nil)
	}

	// TODO(puerco): Befor brute forcing all instances, we could try to guess which
	// instance should be used by looking at the cert issuer.

	var (
		mu       sync.Mutex
		finalRes *verify.VerificationResult
		errs     = make([]error, len(bv.Verifiers))
	)

	t := throttler.New(4, len(bv.Verifiers))
	for i := range bv.Verifiers {
		go func() {
			defer t.Done(nil)

			mu.Lock()
			done := finalRes != nil
			mu.Unlock()
			if done {
				return
			}

			// Run the verification
			res, err := bv.RunVerification(&opts.SigstoreVerification, bv.Verifiers[i], bndl)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				errs[i] = err
			case res == nil:
				errs[i] = errors.New("verifier returned no result")
			case finalRes == nil:
				// No error with a result? Then we got it.
				finalRes = res
			}
		}()
		t.Throttle()
	}

	if finalRes != nil {
		return finalRes, nil
	}

	// No instance verified the bundle. This is a conclusion only when
	// every instance reached one; an instance that could not run may
	// have been the one able to verify it. In that case only the
	// operational errors are wrapped, so the conclusion sentinel does
	// not leak into the chain and get read as a failed verification.
	var conclusions, failures []error
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, api.ErrVerificationFailed):
			conclusions = append(conclusions, err)
		default:
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		msg := "unable to verify with the configured sigstore instances"
		if len(conclusions) > 0 {
			// Rendered as text, not wrapped: the conclusion sentinel must
			// stay out of the chain when nothing was concluded.
			msg += " (other instances concluded: " + errors.Join(conclusions...).Error() + ")"
		}
		return nil, fmt.Errorf("%s: %w", msg, errors.Join(failures...))
	}
	return nil, api.VerificationFailedError("no configured sigstore instance verified the bundle", errors.Join(conclusions...))
}

// BuildSigstoreVerifier creates a configured sigstore verifier from the
// configured options.
// TODO(puerco): Abstract the returned verifier
func (bv *DefaultVerifier) BuildSigstoreVerifier(conf *sigstore.InstanceConfig) (VerifyCapable, error) {
	trustedMaterial, err := bv.assembleTrustedMaterial(conf)
	if err != nil {
		return nil, fmt.Errorf("building trusted materials: %w", err)
	}
	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material assembled")
	}

	// Create the verifier
	sigstoreVerifier, err := verify.NewVerifier(trustedMaterial, bv.buildVerifierConfig(conf)...)
	if err != nil {
		return nil, fmt.Errorf("building sigstore verifier: %w", err)
	}
	return sigstoreVerifier, nil
}

func (bv *DefaultVerifier) assembleTrustedMaterial(conf *sigstore.InstanceConfig) (root.TrustedMaterialCollection, error) {
	// Resolve the trusted root through the single sigstore accessor (embedded
	// when fresh, TUF otherwise, embedded fallback if TUF is unreachable).
	trustedRoot, err := conf.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}
	return root.TrustedMaterialCollection{trustedRoot}, nil
}

// buildVerifierConfig creates a verifier configuration from an options set
func (bv *DefaultVerifier) buildVerifierConfig(conf *sigstore.InstanceConfig) []verify.VerifierOption {
	config := []verify.VerifierOption{}

	vc := conf.VerifierConfig

	if vc.RequireCTlog {
		config = append(config, verify.WithSignedCertificateTimestamps(1))
	}

	if vc.RequireSignedTimestamps {
		config = append(config, verify.WithSignedTimestamps(1))
	}

	if vc.RequireObserverTimestamp {
		config = append(config, verify.WithObserverTimestamps(1))
	}

	if vc.RequireTlog {
		config = append(config, verify.WithTransparencyLog(1))
	}

	return config
}

// RunVerification checks the bundle against one sigstore instance with the
// policy built from the options. Errors that arise before the sigstore
// verifier runs — an undefined identity policy, an invalid expected
// identity, a malformed artifact digest — are plain errors: verification
// could not run. A defect in the bundle itself and any failure reported by
// the sigstore verifier are conclusions, wrapped in
// api.ErrVerificationFailed.
func (bv *DefaultVerifier) RunVerification(
	opts *options.SigstoreVerification, sigstoreVerifier VerifyCapable, bndl *bundle.Bundle,
) (*verify.VerificationResult, error) {
	// Build a deferred verifier here, outside the verification itself, so
	// that failing to build it (trusted root unreachable, bad instance
	// config) reads as "could not run", not as a failed verification.
	if lazy, ok := sigstoreVerifier.(*lazyVerifier); ok {
		built, err := lazy.resolve()
		if err != nil {
			return nil, err
		}
		sigstoreVerifier = built
	}

	// If this is a DSSE envelope, check it as a payload
	dsse := bndl.GetDsseEnvelope()
	if dsse != nil {
		if dsse.GetPayload() == nil {
			return nil, api.VerificationFailedError("DSSE envelope has no payload", nil)
		}
	}

	// Build the identity policy if set in the options
	identityPolicies := []verify.PolicyOption{}
	switch {
	// Only ignore the isentity check if the options is explicitly set
	case opts.SkipIdentityCheck:
		identityPolicies = append(identityPolicies, verify.WithoutIdentitiesUnsafe())

	case opts.ExpectedIssuer != "" || opts.ExpectedIssuerRegex != "" ||
		opts.ExpectedSan != "" || opts.ExpectedSanRegex != "":
		// Here we pass the expected identities to the sigstore-go library
		expectedIdentity, err := verify.NewShortCertificateIdentity(
			opts.ExpectedIssuer,      // Issuer
			opts.ExpectedIssuerRegex, // IssuerRegex
			opts.ExpectedSan,         // SAN
			opts.ExpectedSanRegex,    // SAN regex
		)
		if err != nil {
			return nil, fmt.Errorf("creating expected identity: %w", err)
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(expectedIdentity))
	default:
		return nil, fmt.Errorf("expected certificate issuer/identity not defined")
	}

	// Build the artifact policy if we have a digest in the options
	var artifactPolicy verify.ArtifactPolicyOption
	switch {
	case opts.ArtifactDigest != "":
		hexdigest, err := hex.DecodeString(opts.ArtifactDigest)
		if err != nil {
			return nil, fmt.Errorf("error decoding artifact digest hex string")
		}
		artifactPolicy = verify.WithArtifactDigest(opts.ArtifactDigestAlgo, hexdigest)

	case bndl.GetMessageSignature() != nil && bndl.GetMessageSignature().GetMessageDigest() != nil:
		// When the bundle has a messageSignature with an embedded digest,
		// use it for artifact verification.
		md := bndl.GetMessageSignature().GetMessageDigest()
		algo, err := hashAlgorithmToString(md.GetAlgorithm())
		if err != nil {
			return nil, api.VerificationFailedError("reading message signature digest", err)
		}
		artifactPolicy = verify.WithArtifactDigest(algo, md.GetDigest())

	default:
		logrus.Debug("No artifact hash set, no subject matching will be done")
		artifactPolicy = verify.WithoutArtifactUnsafe()
	}
	res, err := sigstoreVerifier.Verify(
		bndl, verify.NewPolicy(artifactPolicy, identityPolicies...),
	)
	if err != nil {
		return nil, api.VerificationFailedError("verifying", err)
	}

	return res, nil
}

// isSpiffeBundle reports whether the bundle's leaf certificate carries a
// spiffe:// URI SAN. Used to dispatch between the sigstore and SPIFFE paths.
func isSpiffeBundle(bndl *bundle.Bundle) bool {
	vm := bndl.GetVerificationMaterial()
	if vm == nil {
		return false
	}
	var der []byte
	if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		der = chain.GetCertificates()[0].GetRawBytes()
	} else if cert := vm.GetCertificate(); cert != nil {
		der = cert.GetRawBytes()
	}
	if len(der) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	for _, uri := range leaf.URIs {
		if uri.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

// hashAlgorithmToString maps a protobuf HashAlgorithm enum to the string
// expected by sigstore-go's WithArtifactDigest.
func hashAlgorithmToString(algo commonv1.HashAlgorithm) (string, error) {
	//nolint:exhaustive
	switch algo {
	case commonv1.HashAlgorithm_SHA2_256:
		return "sha256", nil
	case commonv1.HashAlgorithm_SHA2_384:
		return "sha384", nil
	case commonv1.HashAlgorithm_SHA2_512:
		return "sha512", nil
	case commonv1.HashAlgorithm_SHA3_256: //nolint:staticcheck // Keeping these for compat
		return "sha3-256", nil
	case commonv1.HashAlgorithm_SHA3_384: //nolint:staticcheck // Keeping these for compat
		return "sha3-384", nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
}
