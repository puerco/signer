// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/signer/bundle"
)

// ArtifactKind is the format of a SignedArtifact.
type ArtifactKind string

const (
	// ArtifactKindBundle is a sigstore bundle (cert chain + DSSE
	// envelope + optional Rekor/TSA), produced by the sigstore and
	// SPIFFE signing backends.
	ArtifactKindBundle ArtifactKind = "sigstore"

	// ArtifactKindEnvelope is a bare DSSE envelope produced by the
	// key signing backend.
	ArtifactKindEnvelope ArtifactKind = "dsse"
)

// SignedArtifact is the polymorphic result of a signing operation. It
// abstracts sigstore bundles, DSSE envelopes, and any future signed formats.
// Callers serialize the artifact via WriteTo and branch on Kind only when
// the underlying format matters.
type SignedArtifact interface {
	// Kind reports the canonical format of this artifact.
	Kind() ArtifactKind

	// MediaType returns an IANA-like media type for the canonical
	// serialization form.
	MediaType() string

	// WriteTo serializes the artifact to its canonical JSON form.
	WriteTo(w io.Writer) (int64, error)
}

// BundleArtifact is the SignedArtifact wrapper for sigstore bundles.
// Produced by the sigstore and SPIFFE signing backends.
type BundleArtifact struct {
	Bundle *sbundle.Bundle
}

var _ SignedArtifact = (*BundleArtifact)(nil)

// Kind returns ArtifactKindBundle.
func (b *BundleArtifact) Kind() ArtifactKind { return ArtifactKindBundle }

// MediaType returns the bundle's media type, falling back to
// the generic sigstore-bundle JSON content type when unset.
func (b *BundleArtifact) MediaType() string {
	if b == nil || b.Bundle == nil {
		return ""
	}
	if mt := b.Bundle.GetMediaType(); mt != "" {
		return mt
	}
	return "application/vnd.dev.sigstore.bundle+json"
}

// WriteTo marshals the bundle as protojson and writes it to w.
func (b *BundleArtifact) WriteTo(w io.Writer) (int64, error) {
	if b == nil || b.Bundle == nil {
		return 0, fmt.Errorf("bundle artifact is nil")
	}
	data, err := protojson.Marshal(b.Bundle)
	if err != nil {
		return 0, fmt.Errorf("marshaling bundle: %w", err)
	}
	n, err := w.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("writing bundle: %w", err)
	}
	return int64(n), nil
}

// EnvelopeArtifact is the SignedArtifact wrapper for DSSE envelopes.
// This is produced by the key signing backend.
type EnvelopeArtifact struct {
	Envelope *sdsse.Envelope

	// Raw preserves the envelope's original serialization when the
	// artifact was parsed from bytes. Transparency log lookups need it:
	// the log stores entries keyed by the hash of the envelope as it
	// was uploaded, which a protojson re-marshal may not reproduce.
	Raw []byte

	// SignatureCerts holds, per signature (index-aligned with
	// Envelope.Signatures), the PEM certificate the producer attached
	// in the non-standard "cert" field some keyless signers (the
	// slsa-github-generator among them) add to DSSE signatures. Nil
	// entries mean the signature carried none.
	SignatureCerts [][]byte
}

var _ SignedArtifact = (*EnvelopeArtifact)(nil)

// Kind returns ArtifactKindEnvelope.
func (e *EnvelopeArtifact) Kind() ArtifactKind { return ArtifactKindEnvelope }

func (e *EnvelopeArtifact) MediaType() string {
	return "application/vnd.dev.dsse.envelope+json"
}

// WriteTo marshals the envelope as multiline-indented protojson and
// writes it to w. Indented output matches the existing
// Signer.WriteDSSEEnvelope convention.
func (e *EnvelopeArtifact) WriteTo(w io.Writer) (int64, error) {
	if e == nil || e.Envelope == nil {
		return 0, fmt.Errorf("envelope artifact is nil")
	}
	marshaler := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	data, err := marshaler.Marshal(e.Envelope)
	if err != nil {
		return 0, fmt.Errorf("marshaling envelope: %w", err)
	}
	n, err := w.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("writing envelope: %w", err)
	}
	return int64(n), nil
}

// ErrUnknownArtifact is returned by ParseArtifact when the data is neither
// a sigstore bundle nor a DSSE envelope.
var ErrUnknownArtifact = errors.New("data is not a sigstore bundle or a DSSE envelope")

// ParseArtifact is the inverse of SignedArtifact.WriteTo: it reads the
// canonical JSON form of a signed artifact and returns the matching
// SignedArtifact. Sigstore bundles are recognized by their top-level
// mediaType, DSSE envelopes by their payloadType. Callers branch on
// Kind() or type-assert to *BundleArtifact / *EnvelopeArtifact when the
// underlying format matters.
func ParseArtifact(data []byte) (SignedArtifact, error) {
	var probe struct {
		MediaType   string `json:"mediaType"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing artifact: %w", err)
	}

	switch {
	case probe.MediaType != "":
		bndl, err := bundle.ParseJSON(data)
		if err != nil {
			return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
		}
		return &BundleArtifact{Bundle: bndl}, nil

	case probe.PayloadType != "":
		env := &sdsse.Envelope{}
		// The envelope may carry non-standard fields (the keyless
		// "cert" extension below); they are read separately.
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, env); err != nil {
			return nil, fmt.Errorf("parsing DSSE envelope: %w", err)
		}
		art := &EnvelopeArtifact{Envelope: env, Raw: data}
		// Sidecar-decode the "cert" extension keyless signers add to
		// each signature. Both decoders keep the array order, so the
		// certificates stay index-aligned with the proto signatures.
		var ext struct {
			Signatures []struct {
				Cert string `json:"cert"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(data, &ext); err == nil && len(ext.Signatures) == len(env.GetSignatures()) {
			certs := make([][]byte, len(ext.Signatures))
			var found bool
			for i, sig := range ext.Signatures {
				if sig.Cert != "" {
					certs[i] = []byte(sig.Cert)
					found = true
				}
			}
			if found {
				art.SignatureCerts = certs
			}
		}
		return art, nil

	default:
		return nil, ErrUnknownArtifact
	}
}
