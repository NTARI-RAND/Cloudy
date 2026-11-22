package techtree

import (
	"crypto/ed25519"
	"errors"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func buildsOnFixture(t testing.TB, count int) (*Tree, []ClaimID, ed25519.PrivateKey) {
	t.Helper()
	tree, err := NewTree(testPlatform)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	ids := make([]ClaimID, count)
	for i := range ids {
		claim, err := NewClaim(testPlatform, pub, KindFact, h(1), h(2), h(3), time.Unix(int64(i+1), 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := claim.Sign(key); err != nil {
			t.Fatal(err)
		}
		ids[i], err = tree.AddClaim(claim)
		if err != nil {
			t.Fatal(err)
		}
	}
	return tree, ids, key
}

func buildsOnReference(t testing.TB, key ed25519.PrivateKey, kind RefKind, from, to ClaimID) Reference {
	t.Helper()
	ref, err := NewReference(testPlatform, key.Public().(ed25519.PublicKey), kind, from, to, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.Sign(key); err != nil {
		t.Fatal(err)
	}
	return ref
}

// Repeatedly scan the accepted reference history until the set of reachable
// claims stops growing. This oracle uses no traversal state from Tree.
func scanBuildsOn(refs []Reference, start, target ClaimID) bool {
	reached := map[ClaimID]bool{start: true}
	for {
		before := len(reached)
		for _, ref := range refs {
			if ref.Kind == RefBuildsOn && reached[ref.From] {
				reached[ref.To] = true
			}
		}
		if reached[target] || before == len(reached) {
			return reached[target]
		}
	}
}

func TestBuildsOnDecisionsMatchLogScanAcrossReplay(t *testing.T) {
	tree, ids, key := buildsOnFixture(t, 24)
	rng := rand.New(rand.NewSource(213))
	kinds := []RefKind{RefBuildsOn, RefBuildsOn, RefBuildsOn, RefCites, RefContests, RefRefutes, RefReproduces}
	var accepted []Reference
	wantAdjacency := make(map[ClaimID][]ClaimID)
	for step := 0; step < 400; step++ {
		if step == 200 {
			log := tree.Log()
			replayed, err := OpenLog(testPlatform, log)
			if err != nil {
				t.Fatal(err)
			}
			if replayed.Head() != tree.Head() || !reflect.DeepEqual(replayed.Log(), log) {
				t.Fatal("replay changed the log or chain head")
			}
			if !reflect.DeepEqual(replayed.buildsOn, wantAdjacency) {
				t.Fatal("replay changed the builds_on adjacency")
			}
			for _, from := range ids {
				for _, to := range ids {
					want := scanBuildsOn(accepted, from, to)
					if got := replayed.buildsOnReaches(from, to); got != want {
						t.Fatalf("replayed path %x to %x: got %t, want %t", from[:4], to[:4], got, want)
					}
				}
			}
			tree = replayed
		}
		from, to := rng.Intn(len(ids)), rng.Intn(len(ids)-1)
		if to >= from {
			to++
		}
		ref := buildsOnReference(t, key, kinds[rng.Intn(len(kinds))], ids[from], ids[to])
		var want error
		if ref.Kind == RefBuildsOn && scanBuildsOn(accepted, ref.To, ref.From) {
			want = ErrBuildsOnCycle
		}

		head := tree.Head()
		_, err := tree.AddReference(ref)
		if err != want {
			t.Fatalf("step %d (%s %d to %d): got %v, want %v", step, ref.Kind, from, to, err, want)
		}
		if err == nil {
			accepted = append(accepted, ref)
			if ref.Kind == RefBuildsOn {
				wantAdjacency[ref.From] = append(wantAdjacency[ref.From], ref.To)
			}
			head = tree.Head()
			if _, err := tree.AddReference(ref); !errors.Is(err, ErrDuplicate) {
				t.Fatalf("step %d: resubmission got %v, want %v", step, err, ErrDuplicate)
			}
		}
		if tree.Head() != head || len(tree.log) != len(ids)+len(accepted) {
			t.Fatalf("step %d: a rejected reference changed accepted history", step)
		}
	}
	if !reflect.DeepEqual(tree.buildsOn, wantAdjacency) {
		t.Fatal("adjacency must contain each accepted builds_on reference exactly once")
	}
}

func BenchmarkBuildsOnInsertionCheck(b *testing.B) {
	for _, shape := range []string{"chain", "branches"} {
		for _, unrelated := range []int{0, 1024} {
			name := shape + "/local"
			if unrelated != 0 {
				name = shape + "/with_unrelated_history"
			}
			b.Run(name, func(b *testing.B) {
				const reachable = 127
				tree, ids, key := buildsOnFixture(b, reachable+1+unrelated)
				for child := 1; child < reachable; child++ {
					parent := child - 1
					if shape == "branches" {
						parent /= 2
					}
					ref := buildsOnReference(b, key, RefBuildsOn, ids[parent], ids[child])
					if _, err := tree.AddReference(ref); err != nil {
						b.Fatal(err)
					}
				}
				for i := reachable + 1; i < len(ids); i++ {
					ref := buildsOnReference(b, key, RefBuildsOn, ids[i], ids[reachable])
					if _, err := tree.AddReference(ref); err != nil {
						b.Fatal(err)
					}
				}
				// Submit a duplicate so every iteration runs the full insertion
				// validation with a failed reachability search and identical history.
				ref := buildsOnReference(b, key, RefBuildsOn, ids[reachable], ids[0])
				if _, err := tree.AddReference(ref); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := tree.AddReference(ref); !errors.Is(err, ErrDuplicate) {
						b.Fatalf("got %v, want %v", err, ErrDuplicate)
					}
				}
			})
		}
	}
}
