package bundle

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/kuasar-sandbox/accelerator/pkg/manifest/codec"
	manifestcrypto "github.com/kuasar-sandbox/accelerator/pkg/manifest/crypto"
	"github.com/kuasar-sandbox/accelerator/pkg/manifest/delta"
	"github.com/kuasar-sandbox/accelerator/pkg/store"
)

// Delta-compressed chunks in Bundles.
//
// A Bundle writer never produces delta objects (ingest disables delta for
// bundle writers: a delta's base is some other image's chunk, which a
// self-contained Bundle would then have to carry in full, making the Bundle
// larger rather than smaller). A Bundle can still contain delta objects when
// it is a copy of a store image (CopyManifest) or was uploaded from one, so
// verification, upload and copy understand them:
//
//   - a Version2 manifest's delta table names each delta entry's base; the
//     closure of a manifest is its entries' objects plus those bases, and all of
//     them must be present in the Bundle (validateManifestClosure);
//   - a base referenced only through the delta table is still "referenced": it
//     is uploaded with the Bundle and does not count as an unreferenced Chunk;
//   - a delta entry is verified by opening the delta object with its key-table
//     key, checking that it names the base the manifest said it does, decrypting
//     that base with the key the delta carries, and applying the stream. The
//     base's bytes are hash-checked like every other object. Depth is one: a
//     base that is itself a delta object is rejected.

// refKind says how a manifest references a chunk object.
type refKind uint8

const (
	// refChunk: an entry addresses the object and it is an independent chunk.
	refChunk refKind = iota
	// refDelta: an entry addresses the object and it is a delta object.
	refDelta
	// refBase: no entry addresses the object; a delta entry depends on it.
	// decryptKey is unknown (it lives inside the delta object).
	refBase
)

// manifestChunkRefs reports every chunk object the manifest references, with
// how it references it, to add. keys are the unsealed per-entry keys.
func manifestChunkRefs(manifest *codec.Manifest, keys [][32]byte, add func(store.ContentKey, chunkReference) error) error {
	for index, entry := range manifest.Entries {
		if entry.IsZero {
			continue
		}
		reference := chunkReference{decryptKey: keys[index], plainSize: entry.Size}
		if entry.IsDelta {
			ref, ok := manifest.DeltaFor(index)
			if !ok {
				return fmt.Errorf("manifest bundle: entry %d is flagged delta without a delta ref", index)
			}
			reference.kind = refDelta
			reference.base = store.ContentKey(ref.Base)
			reference.baseSize = ref.BaseSize
		}
		if err := add(store.ContentKey(entry.CiphertextHash), reference); err != nil {
			return err
		}
	}
	for _, ref := range manifest.Deltas {
		if err := add(store.ContentKey(ref.Base), chunkReference{kind: refBase, plainSize: ref.BaseSize}); err != nil {
			return err
		}
	}
	return nil
}

// mergeChunkReference reconciles two references to the same object. An
// entry's reference (which knows the key) wins over a base-only reference,
// provided the sizes agree; two entry references must be identical; and a
// base may not be a delta object.
func mergeChunkReference(key store.ContentKey, previous, next chunkReference) (chunkReference, error) {
	if previous.plainSize != next.plainSize {
		return chunkReference{}, fmt.Errorf("manifest bundle: Chunk %s has inconsistent plaintext size across references", hex.EncodeToString(key[:]))
	}
	switch {
	case previous.kind == refBase && next.kind == refBase:
		return previous, nil
	case previous.kind == refBase:
		if next.kind == refDelta {
			return chunkReference{}, fmt.Errorf("manifest bundle: Chunk %s is both a delta object and another delta's base", hex.EncodeToString(key[:]))
		}
		return next, nil
	case next.kind == refBase:
		if previous.kind == refDelta {
			return chunkReference{}, fmt.Errorf("manifest bundle: Chunk %s is both a delta object and another delta's base", hex.EncodeToString(key[:]))
		}
		return previous, nil
	}
	if previous != next {
		return chunkReference{}, fmt.Errorf("manifest bundle: Chunk %s has inconsistent key or plaintext size across Manifests", hex.EncodeToString(key[:]))
	}
	return previous, nil
}

// manifestClosureKeys lists every chunk object a manifest needs: its entries'
// objects and its deltas' bases, each once, in manifest order.
func manifestClosureKeys(manifest *codec.Manifest) []store.ContentKey {
	seen := make(map[store.ContentKey]struct{}, len(manifest.Entries)+len(manifest.Deltas))
	keys := make([]store.ContentKey, 0, len(manifest.Entries)+len(manifest.Deltas))
	add := func(k store.ContentKey) {
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for _, entry := range manifest.Entries {
		if !entry.IsZero {
			add(store.ContentKey(entry.CiphertextHash))
		}
	}
	for _, ref := range manifest.Deltas {
		add(store.ContentKey(ref.Base))
	}
	return keys
}

// baseGetter returns the verified physical bytes of a base object. release
// must be called once the bytes are no longer needed.
type baseGetter func(ctx context.Context, key store.ContentKey) (physical []byte, release func(), err error)

// verifyChunkPlaintext proves that physical (already hash-checked against key)
// decodes under reference: an independent chunk decrypts and decompresses into
// plain; a delta opens, names the expected base, and applies onto its base's
// plaintext into plain; a base-only reference has nothing to decode here (it
// is decoded when one of its dependents is verified).
func verifyChunkPlaintext(ctx context.Context, decryptor manifestcrypto.Decryptor, key store.ContentKey, reference chunkReference, physical, plain []byte, getBase baseGetter) error {
	switch reference.kind {
	case refBase:
		if len(physical) == 0 || physical[0] == manifestcrypto.ChunkFormatAESDelta {
			return fmt.Errorf("manifest bundle: Chunk %s is a delta's base but is itself a delta object", hex.EncodeToString(key[:]))
		}
		return nil
	case refChunk:
		if len(physical) > 0 && physical[0] == manifestcrypto.ChunkFormatAESDelta {
			return fmt.Errorf("manifest bundle: Chunk %s is a delta object but its Manifest entry is not flagged delta", hex.EncodeToString(key[:]))
		}
		if err := decryptor.DecryptChunkTo(ctx, reference.decryptKey, physical, plain); err != nil {
			return fmt.Errorf("manifest bundle: Chunk %s decrypt/decompress: %w", hex.EncodeToString(key[:]), err)
		}
		return nil
	}

	opener, ok := decryptor.(manifestcrypto.DeltaDecryptor)
	if !ok {
		return fmt.Errorf("manifest bundle: Chunk %s is a delta object but the decryptor cannot open deltas", hex.EncodeToString(key[:]))
	}
	opened, err := opener.OpenDeltaChunk(ctx, reference.decryptKey, physical)
	if err != nil {
		return fmt.Errorf("manifest bundle: Chunk %s open delta: %w", hex.EncodeToString(key[:]), err)
	}
	defer clear(opened.BaseKey[:])
	if store.ContentKey(opened.Header.BaseObjectKey) != reference.base || opened.Header.BaseSize != reference.baseSize {
		return fmt.Errorf("manifest bundle: Chunk %s names base %s (%d B), its Manifest says %s (%d B)",
			hex.EncodeToString(key[:]), hex.EncodeToString(opened.Header.BaseObjectKey[:4]), opened.Header.BaseSize,
			hex.EncodeToString(reference.base[:4]), reference.baseSize)
	}
	if opened.Header.TargetSize != reference.plainSize {
		return fmt.Errorf("manifest bundle: Chunk %s delta target size %d, Manifest entry size %d", hex.EncodeToString(key[:]), opened.Header.TargetSize, reference.plainSize)
	}
	baseBytes, release, err := getBase(ctx, reference.base)
	if err != nil {
		return fmt.Errorf("manifest bundle: Chunk %s base %s: %w", hex.EncodeToString(key[:]), hex.EncodeToString(reference.base[:]), err)
	}
	defer release()
	if len(baseBytes) == 0 || baseBytes[0] == manifestcrypto.ChunkFormatAESDelta {
		return fmt.Errorf("manifest bundle: Chunk %s base %s is itself a delta object (depth one)", hex.EncodeToString(key[:]), hex.EncodeToString(reference.base[:]))
	}
	basePlain := make([]byte, reference.baseSize)
	defer clear(basePlain)
	if err := decryptor.DecryptChunkTo(ctx, opened.BaseKey, baseBytes, basePlain); err != nil {
		return fmt.Errorf("manifest bundle: Chunk %s base %s decrypt: %w", hex.EncodeToString(key[:]), hex.EncodeToString(reference.base[:]), err)
	}
	if err := delta.ApplyTo(basePlain, opened.Stream, plain); err != nil {
		return fmt.Errorf("manifest bundle: Chunk %s apply delta: %w", hex.EncodeToString(key[:]), err)
	}
	return nil
}
