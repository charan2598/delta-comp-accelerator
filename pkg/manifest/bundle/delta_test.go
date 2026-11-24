package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/kuasar-sandbox/accelerator/pkg/manifest/codec"
	manifestcrypto "github.com/kuasar-sandbox/accelerator/pkg/manifest/crypto"
	"github.com/kuasar-sandbox/accelerator/pkg/manifest/delta"
	"github.com/kuasar-sandbox/accelerator/pkg/store"
)

// deltaBundleFixture is a store-like object set with two images: v0, one
// independent chunk; v1, a Version2 manifest whose single entry is a delta of
// v0's chunk. The base is therefore outside v1's entries.
type deltaBundleFixture struct {
	admission store.WriteAdmission
	customer  [32]byte
	dec       manifestcrypto.Decryptor
	enc       manifestcrypto.Encryptor

	baseObj, deltaObj         []byte
	baseKey, deltaKey         store.ContentKey
	v0, v1                    []byte // manifest blobs
	v0Key, v1Key              store.ContentKey
	target                    []byte
	kBase, kDelta, wrongKBase [32]byte
}

func newDeltaBundleFixture(t *testing.T) *deltaBundleFixture {
	t.Helper()
	salt, err := store.SaltForGeneration("G1")
	if err != nil {
		t.Fatal(err)
	}
	f := &deltaBundleFixture{admission: store.WriteAdmission{Generation: "G1", Salt: salt}}
	f.customer[0] = 0x42
	f.enc, f.dec, err = manifestcrypto.New(manifestcrypto.Config{Chunk: "aes", Manifest: "aes"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := bytes.Repeat([]byte("bundle-base-block-"), 2000)
	f.target = append([]byte(nil), base...)
	f.target[77] ^= 0x11
	f.target[20000] ^= 0x22

	var baseHash [32]byte
	f.baseObj, baseHash, f.kBase, err = f.enc.EncryptChunk(ctx, salt, base)
	if err != nil {
		t.Fatal(err)
	}
	f.baseKey = store.ContentKey(baseHash)
	stream := delta.Encode(base, f.target)
	var deltaHash [32]byte
	f.deltaObj, deltaHash, f.kDelta, err = f.enc.(manifestcrypto.DeltaEncryptor).EncryptDeltaChunk(ctx, salt, manifestcrypto.DeltaBase{
		ObjectKey: baseHash, Key: f.kBase, PlaintextSize: len(base),
	}, f.target, stream)
	if err != nil {
		t.Fatal(err)
	}
	f.deltaKey = store.ContentKey(deltaHash)

	m0 := &codec.Manifest{Version: codec.Version1, ChunkMode: codec.ChunkModeFixed, ImageSize: uint64(len(base)),
		MinChunkSize: uint32(len(base)), MaxChunkSize: uint32(len(base)),
		Entries: []codec.ChunkEntry{{Size: uint32(len(base)), CiphertextHash: baseHash}}}
	f.v0 = marshalWithKey(t, f.enc, m0, f.customer, f.kBase)
	f.v0Key = store.ContentKey(sha256.Sum256(f.v0))

	m1 := &codec.Manifest{Version: codec.Version2, ChunkMode: codec.ChunkModeFixed, ImageSize: uint64(len(f.target)),
		MinChunkSize: uint32(len(f.target)), MaxChunkSize: uint32(len(f.target)),
		Entries: []codec.ChunkEntry{{Size: uint32(len(f.target)), CiphertextHash: deltaHash, IsDelta: true}},
		Deltas:  []codec.DeltaRef{{Entry: 0, BaseSize: uint32(len(base)), Base: baseHash}}}
	f.v1 = marshalWithKey(t, f.enc, m1, f.customer, f.kDelta)
	f.v1Key = store.ContentKey(sha256.Sum256(f.v1))
	return f
}

// bundle writes the given objects into a Bundle rooted at root.
func (f *deltaBundleFixture) bundle(t *testing.T, root store.ContentKey, chunks map[store.ContentKey][]byte, manifests map[store.ContentKey][]byte) *Reader {
	t.Helper()
	var out bytes.Buffer
	w, err := NewWriter(&out, f.admission, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for k, v := range chunks {
		if _, err := w.Put(ctx, f.admission, store.PartitionChunk, k, v); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range manifests {
		if _, err := w.Put(ctx, f.admission, store.PartitionManifest, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finalize(root); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func (f *deltaBundleFixture) store() *routeGetter {
	return &routeGetter{objects: map[store.Partition]map[store.ContentKey][]byte{
		store.PartitionChunk:    {f.baseKey: f.baseObj, f.deltaKey: f.deltaObj},
		store.PartitionManifest: {f.v0Key: f.v0, f.v1Key: f.v1},
	}}
}

// Checks that a Bundle holding only the root Manifest v1, its delta, and the base
// passes FullVerify. The base is present only through v1's delta table. Checks that
// Upload sends the base and the delta to the target and publishes the root last,
// and that VerifyExactManifests accepts the same closure.
func TestBundleFullVerifyAcceptsDeltaWithExternalBase(t *testing.T) {
	f := newDeltaBundleFixture(t)
	// Only v1 is in the Bundle; its base is present because the delta table
	// makes it part of v1's closure, not because any entry addresses it.
	r := f.bundle(t, f.v1Key, map[store.ContentKey][]byte{f.baseKey: f.baseObj, f.deltaKey: f.deltaObj},
		map[store.ContentKey][]byte{f.v1Key: f.v1})
	if err := r.FullVerify(context.Background(), f.v1Key, f.customer, f.dec, VerifyOptions{Workers: 2}); err != nil {
		t.Fatalf("FullVerify: %v", err)
	}
	// Upload publishes the base too (it must reach the target before any
	// reader can be handed v1).
	target := &recordingExactStore{accepted: f.admission, pool: 2}
	if err := r.Upload(context.Background(), f.v1Key, f.customer, f.dec, target, VerifyOptions{Workers: 2}); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	_, _, puts := target.snapshot()
	var sawBase, sawDelta bool
	for i, p := range puts {
		switch {
		case p.partition == store.PartitionChunk && p.key == f.baseKey:
			sawBase = true
		case p.partition == store.PartitionChunk && p.key == f.deltaKey:
			sawDelta = true
		case p.partition == store.PartitionManifest && p.key == f.v1Key:
			if i != len(puts)-1 {
				t.Fatal("root manifest was not published last")
			}
		}
	}
	if !sawBase || !sawDelta {
		t.Fatalf("upload missed objects: base=%v delta=%v", sawBase, sawDelta)
	}

	// Verifying the selected closure across Bundles works the same way.
	if err := VerifyExactManifests(context.Background(), ExactManifest{Reader: r, Key: f.v1Key}, nil, f.customer, f.dec, VerifyOptions{Workers: 2}); err != nil {
		t.Fatalf("VerifyExactManifests: %v", err)
	}
}

// Checks that a delta whose base is absent from the Bundle fails FullVerify with
// ErrIncomplete, and that the error names the base.
func TestBundleDeltaBaseMissingIsIncomplete(t *testing.T) {
	f := newDeltaBundleFixture(t)
	r := f.bundle(t, f.v1Key, map[store.ContentKey][]byte{f.deltaKey: f.deltaObj}, map[store.ContentKey][]byte{f.v1Key: f.v1})
	err := r.FullVerify(context.Background(), f.v1Key, f.customer, f.dec, VerifyOptions{})
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "base") {
		t.Fatalf("FullVerify without the base = %v, want ErrIncomplete naming the base", err)
	}
}

// Checks that each of three kinds of tampering fails verification: a manifest whose
// delta table names a different base, a base that is missing or corrupt, and a
// delta object whose Version 1 entry is not flagged as a delta. Each case is a
// subtest.
func TestBundleDeltaVerificationCatchesTampering(t *testing.T) {
	f := newDeltaBundleFixture(t)
	ctx := context.Background()

	t.Run("manifest names another base", func(t *testing.T) {
		// A Version2 manifest whose table names a different (present) object as
		// the base. The key table is sealed over the table, so re-seal; the delta
		// object itself still names the real base and must be caught.
		other, otherHash, _, err := f.enc.EncryptChunk(ctx, f.admission.Salt, bytes.Repeat([]byte{0x5c}, len(f.target)))
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := codec.Unmarshal(f.v1)
		if err != nil {
			t.Fatal(err)
		}
		m.Deltas[0].Base = otherHash
		bad := marshalWithKey(t, f.enc, m, f.customer, f.kDelta)
		badKey := store.ContentKey(sha256.Sum256(bad))
		r := f.bundle(t, badKey, map[store.ContentKey][]byte{f.deltaKey: f.deltaObj, store.ContentKey(otherHash): other},
			map[store.ContentKey][]byte{badKey: bad})
		err = r.FullVerify(ctx, badKey, f.customer, f.dec, VerifyOptions{})
		if err == nil || !strings.Contains(err.Error(), "names base") {
			t.Fatalf("FullVerify = %v, want base disagreement", err)
		}
	})

	t.Run("base object corrupted", func(t *testing.T) {
		corrupt := append([]byte(nil), f.baseObj...)
		corrupt[len(corrupt)-1] ^= 1
		corruptKey := store.ContentKey(sha256.Sum256(corrupt))
		// The Bundle holds the corrupt bytes under their own (correct) key, so
		// the base the delta names is simply absent; and under the original key
		// the hash check fails. Either way verification must not pass.
		r := f.bundle(t, f.v1Key, map[store.ContentKey][]byte{f.deltaKey: f.deltaObj, corruptKey: corrupt},
			map[store.ContentKey][]byte{f.v1Key: f.v1})
		if err := r.FullVerify(ctx, f.v1Key, f.customer, f.dec, VerifyOptions{}); err == nil {
			t.Fatal("FullVerify passed with the base missing/corrupt")
		}
	})

	t.Run("entry not flagged for a delta object", func(t *testing.T) {
		m, _, err := codec.Unmarshal(f.v1)
		if err != nil {
			t.Fatal(err)
		}
		m.Version = codec.Version1
		m.Entries[0].IsDelta = false
		m.Deltas = nil
		v1asV1 := marshalWithKey(t, f.enc, m, f.customer, f.kDelta)
		k := store.ContentKey(sha256.Sum256(v1asV1))
		r := f.bundle(t, k, map[store.ContentKey][]byte{f.deltaKey: f.deltaObj, f.baseKey: f.baseObj, store.ContentKey(sha256.Sum256(f.baseObj)): f.baseObj},
			map[store.ContentKey][]byte{k: v1asV1, f.v0Key: f.v0})
		err = r.FullVerify(ctx, k, f.customer, f.dec, VerifyOptions{})
		if err == nil || !strings.Contains(err.Error(), "not flagged delta") {
			t.Fatalf("FullVerify = %v, want unflagged delta object rejected", err)
		}
	})
}

// Checks that CopyManifest copies a Version 2 Manifest's delta base even though no
// entry of that Manifest addresses it, and that the copied Bundle verifies. Also
// checks that a Bundle holding both v0 and v1 verifies with the base shared.
func TestBundleCopyManifestIncludesDeltaBases(t *testing.T) {
	f := newDeltaBundleFixture(t)
	var out bytes.Buffer
	w, err := NewWriter(&out, f.admission, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Copy only v1 from a store that also holds v0: the base must come along
	// although no entry of v1 addresses it.
	if err := w.CopyManifest(context.Background(), f.v1Key, f.store()); err != nil {
		t.Fatalf("CopyManifest: %v", err)
	}
	if err := w.Finalize(f.v1Key); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.HasChunk(f.baseKey) || !r.HasChunk(f.deltaKey) {
		t.Fatalf("copied Bundle lacks objects: base=%v delta=%v", r.HasChunk(f.baseKey), r.HasChunk(f.deltaKey))
	}
	if err := r.FullVerify(context.Background(), f.v1Key, f.customer, f.dec, VerifyOptions{}); err != nil {
		t.Fatalf("FullVerify of the copy: %v", err)
	}

	// Shared base: a Bundle holding both v0 (which addresses the base as a
	// chunk) and v1 (which needs it as a base) verifies, with the base counted
	// once and decrypted under the key v0's table holds.
	both := f.bundle(t, f.v1Key, map[store.ContentKey][]byte{f.baseKey: f.baseObj, f.deltaKey: f.deltaObj},
		map[store.ContentKey][]byte{f.v0Key: f.v0, f.v1Key: f.v1})
	if err := both.FullVerify(context.Background(), f.v1Key, f.customer, f.dec, VerifyOptions{}); err != nil {
		t.Fatalf("FullVerify with shared base: %v", err)
	}
}
