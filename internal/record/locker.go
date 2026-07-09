package record

// Locker is member-local, ERASABLE content storage: the half of the record
// that never touches the commons. It is type-disjoint from Store and Log —
// it speaks []byte and Hash, never Entry — so storing content in a log is a
// type error, not a code-review catch. Erase exists here and nowhere else in
// the package.
type Locker interface {
	// Put stores content locally and returns its commons hash (HashContent
	// of the bytes).
	Put(content []byte) Hash
	// Get returns the content for h if still held.
	Get(h Hash) ([]byte, bool)
	// Erase forgets the content for h; the commons keeps only the hash and
	// never notices.
	Erase(h Hash)
}

// memLocker is the in-memory Locker.
type memLocker struct {
	m map[Hash][]byte
}

// NewMemLocker returns an in-memory Locker.
func NewMemLocker() Locker {
	return &memLocker{m: make(map[Hash][]byte)}
}

// Put implements Locker.
func (l *memLocker) Put(content []byte) Hash {
	h := HashContent(content)
	l.m[h] = append([]byte(nil), content...)
	return h
}

// Get implements Locker.
func (l *memLocker) Get(h Hash) ([]byte, bool) {
	b, ok := l.m[h]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

// Erase implements Locker.
func (l *memLocker) Erase(h Hash) {
	delete(l.m, h)
}
