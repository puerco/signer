// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"

	"github.com/policylabs/signer/key"
)

// KeysSign is a command.OptionsSet for sign-side private-key configuration.
// It is the sister of upstream carabiner-dev/command/keys.Options
// (which handles verify-side public keys): both let CLI tools wire
// flag-driven key-file paths into their command surface.
//
// When the resolved Signer.Options.Backend is BackendKey, the keys
// produced by KeysSign.ParseSigningKeys feed into Signer.Options.Keys,
// at which point Signer.SignStatement / SignMessage produce DSSE
// envelopes via the key backend.
type KeysSign struct {
	// PrivateKeyPaths are filesystem paths to private signing keys.
	// Bound to --signing-key (repeatable).
	PrivateKeyPaths []string

	// PassphraseEnvVar names an environment variable whose value (when
	// set and non-empty) is used to decrypt encrypted signing keys
	// (currently only encrypted GPG private keys). Bound to
	// --signing-key-passphrase-env.
	PassphraseEnvVar string

	// CertificatePath is the path to the certificate issued to the first
	// signing key. Bound to --signing-cert. When set, bundles produced
	// with the key backend carry the certificate (and the chain below)
	// as verification material instead of a key hint.
	CertificatePath string

	// CertificateChainPaths are paths to the intermediate certificates
	// of CertificatePath, in PEM. Bound to --signing-cert-chain
	// (repeatable); each file may hold several certificates.
	CertificateChainPaths []string

	// extraKeys are programmatically supplied providers (via AddKeys).
	// Returned by ParseSigningKeys ahead of any file-loaded keys.
	extraKeys []key.PrivateKeyProvider

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*KeysSign)(nil)

// defaultPassphraseEnvVar is the env-var name a CLI looks at by
// default when an encrypted signing key needs decryption. Callers can
// override on the resulting KeysSign or via the
// --signing-key-passphrase-env flag.
const defaultPassphraseEnvVar = "SIGNING_KEY_PASSPHRASE"

const (
	flagSigningKey              = "signing-key"
	flagSigningKeyPassphraseEnv = "signing-key-passphrase-env"
	flagSigningCert             = "signing-cert"
	flagSigningCertChain        = "signing-cert-chain"
)

// DefaultKeysSign returns a KeysSign ready to bind flags. The
// passphrase env-var name defaults to SIGNING_KEY_PASSPHRASE; users
// who export that variable get encrypted-key support out of the box,
// users who don't see no behavior change.
func DefaultKeysSign() *KeysSign {
	return &KeysSign{
		PassphraseEnvVar: defaultPassphraseEnvVar,
	}
}

// Config returns the flag configuration for KeysSign.
func (k *KeysSign) Config() *command.OptionsSetConfig {
	if k.config == nil {
		k.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagSigningKey: {
					Short: "K",
					Long:  flagSigningKey,
					Help:  "path to a private signing key file (PEM PKCS#8/PKCS#1/SEC1 or OpenPGP)",
				},
				flagSigningKeyPassphraseEnv: {
					Long: flagSigningKeyPassphraseEnv,
					Help: "envvar to read the signing key passphrase from",
				},
				flagSigningCert: {
					Long: flagSigningCert,
					Help: "path to the PEM certificate issued to the signing key, recorded in bundles instead of a key hint",
				},
				flagSigningCertChain: {
					Long: flagSigningCertChain,
					Help: "path to PEM intermediate certificates of the signing certificate (repeatable)",
				},
			},
		}
	}
	return k.config
}

// AddFlags registers the KeysSign flags on cmd.
func (k *KeysSign) AddFlags(cmd *cobra.Command) {
	cfg := k.Config()
	pf := cmd.PersistentFlags()
	pf.StringSliceVarP(
		&k.PrivateKeyPaths,
		cfg.LongFlag(flagSigningKey),
		cfg.ShortFlag(flagSigningKey),
		k.PrivateKeyPaths,
		cfg.HelpText(flagSigningKey),
	)
	pf.StringVar(
		&k.PassphraseEnvVar,
		cfg.LongFlag(flagSigningKeyPassphraseEnv),
		k.PassphraseEnvVar,
		cfg.HelpText(flagSigningKeyPassphraseEnv),
	)
	pf.StringVar(
		&k.CertificatePath,
		cfg.LongFlag(flagSigningCert),
		k.CertificatePath,
		cfg.HelpText(flagSigningCert),
	)
	pf.StringSliceVar(
		&k.CertificateChainPaths,
		cfg.LongFlag(flagSigningCertChain),
		k.CertificateChainPaths,
		cfg.HelpText(flagSigningCertChain),
	)
}

// Validate checks that every configured signing-key path exists. It
// does not parse the key material — that happens lazily in
// ParseSigningKeys so flag-time errors stay cheap and parsing errors
// surface with file context at use time.
func (k *KeysSign) Validate() error {
	var errs []error
	for _, p := range k.PrivateKeyPaths {
		if _, err := os.Stat(p); err != nil {
			errs = append(errs, fmt.Errorf("checking signing key %q: %w", p, err))
		}
	}
	if k.CertificatePath != "" {
		if _, err := os.Stat(k.CertificatePath); err != nil {
			errs = append(errs, fmt.Errorf("checking signing certificate %q: %w", k.CertificatePath, err))
		}
	}
	if k.CertificatePath == "" && len(k.CertificateChainPaths) > 0 {
		errs = append(errs, fmt.Errorf("--%s requires --%s", flagSigningCertChain, flagSigningCert))
	}
	for _, p := range k.CertificateChainPaths {
		if _, err := os.Stat(p); err != nil {
			errs = append(errs, fmt.Errorf("checking certificate chain file %q: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// AddKeys appends pre-parsed providers. They are returned by
// ParseSigningKeys ahead of any keys loaded from PrivateKeyPaths.
// Useful for tests and for callers that already hold the key material
// and want to feed it to the same plumbing as the file-based keys.
func (k *KeysSign) AddKeys(providers ...key.PrivateKeyProvider) {
	k.extraKeys = append(k.extraKeys, providers...)
}

// BuildSigner returns a *Signer wired for the key backend: Backend
// set to BackendKey and Keys populated from ParseSigningKeys. Errors
// when no keys are configured (a key-backend signer with no keys
// can't sign).
func (k *KeysSign) BuildSigner() (*Signer, error) {
	keys, err := k.ParseSigningKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("KeysSign.BuildSigner: no signing keys configured")
	}
	chain, err := k.ParseCertificateChain()
	if err != nil {
		return nil, err
	}
	target := DefaultSigner
	target.Backend = BackendKey
	target.Keys = keys
	target.CertificateChain = chain
	return &target, nil
}

// ParseCertificateChain reads the signing certificate and its
// intermediates, leaf first. It returns nil when no certificate is
// configured.
func (k *KeysSign) ParseCertificateChain() ([]*x509.Certificate, error) {
	if k.CertificatePath == "" {
		return nil, nil
	}
	leaf, err := readPEMCertificates(k.CertificatePath)
	if err != nil {
		return nil, fmt.Errorf("reading signing certificate: %w", err)
	}
	if len(leaf) != 1 {
		return nil, fmt.Errorf("signing certificate file %q must hold exactly one certificate, found %d", k.CertificatePath, len(leaf))
	}
	chain := leaf
	for _, p := range k.CertificateChainPaths {
		certs, err := readPEMCertificates(p)
		if err != nil {
			return nil, fmt.Errorf("reading certificate chain: %w", err)
		}
		chain = append(chain, certs...)
	}
	return chain, nil
}

// readPEMCertificates reads every certificate in a PEM file.
func readPEMCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return certs, nil
}

// ParseSigningKeys reads and parses every entry in PrivateKeyPaths
// and returns the resulting providers prepended with AddKeys-supplied
// extras. Encrypted GPG keys are decrypted using the passphrase read
// from PassphraseEnvVar when set.
func (k *KeysSign) ParseSigningKeys() ([]key.PrivateKeyProvider, error) {
	parser := key.NewParser()

	var fnOpts []key.FnOpt
	if k.PassphraseEnvVar != "" {
		if passphrase := os.Getenv(k.PassphraseEnvVar); passphrase != "" {
			fnOpts = append(fnOpts, key.WithPassphrase(passphrase))
		}
	}

	out := append([]key.PrivateKeyProvider{}, k.extraKeys...)
	for _, p := range k.PrivateKeyPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading signing key file %s: %w", p, err)
		}
		provider, err := parser.ParsePrivateKeyProvider(data, fnOpts...)
		if err != nil {
			return nil, fmt.Errorf("parsing signing key %s: %w", p, err)
		}
		out = append(out, provider)
	}
	return out, nil
}
