package secrets

import (
	"io"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/secret"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	MaxBytes = 1 << 20
)

var (
	ErrMaxSizeExceeded = errors.New("Secret:MaxSizeExceeded")
)

type StreamOptions struct {
	Strength  crypto.Strength
	BlockSize uint64
	BatchSize uint64
	Canceler  <-chan struct{}
}

func WithCanceler(cancel <-chan struct{}) func(*StreamOptions) {
	return func(w *StreamOptions) {
		w.Canceler = cancel
	}
}

func WithBlockSize(blockSize uint64) func(*StreamOptions) {
	return func(w *StreamOptions) {
		w.BlockSize = blockSize
	}
}

func WithBatchSize(batchSize uint64) func(*StreamOptions) {
	return func(w *StreamOptions) {
		w.BatchSize = batchSize
	}
}

func WithStrength(s crypto.Strength) func(*StreamOptions) {
	return func(w *StreamOptions) {
		w.Strength = s
	}
}

func WithStreamOptions(o StreamOptions) func(*StreamOptions) {
	return func(w *StreamOptions) {
		*w = o
	}
}

func BuildStreamOptions(o ...func(*StreamOptions)) (ret StreamOptions) {
	ret = StreamOptions{crypto.Moderate, 1 << 17, 4, nil}
	// ret = StreamOptions{crypto.Moderate, 1, 4, nil}
	for _, fn := range o {
		fn(&ret)
	}
	return
}

// A block writer converts plaintext data into a stream of encrypted blocks.
type BlockWriter interface {

	// Encrypts the input and returns a block. Blocks are guaranteed to
	// be indexed in the order they are created.
	Write([]byte) (secret.Block, error)
}

// A block decrypter.
type BlockReader interface {
	Read(secret.Block) ([]byte, error)
}

// Downloads the block stream for the secret, decrypts it and writes to the dst.
// Upon completion, a digest of the value is returned
func Download(client secret.Transport, t auth.SignedToken, cur secret.Secret, r BlockReader, dst io.Writer, o ...func(*StreamOptions)) (digest []byte, err error) {
	opts := BuildStreamOptions(o...)

	hsh := cur.AuthorSig.Hash.New()
	defer func() {
		digest = hsh.Sum(nil)
	}()

	done, blocks := make(chan error), make(chan []secret.Block)
	go func() {
		for i := 0; i < cur.StreamSize; {
			batch, err := client.LoadBlocks(t, cur.OrgId, cur.Id, cur.Version,
				page.BuildPage(
					page.Offset(uint64(i)),
					page.Limit(opts.BatchSize)))
			if err != nil {
				done <- err
				return
			}

			select {
			case <-opts.Canceler:
				done <- errs.CanceledError
				return
			case blocks <- batch:
			}

			i += len(batch)
		}

		done <- nil
	}()

	for {
		var batch []secret.Block
		select {
		case err = <-done:
			return
		case batch = <-blocks:
		}

		for _, block := range batch {
			data, err := r.Read(block)
			if err != nil {
				return nil, err
			}

			if _, err := dst.Write(data); err != nil {
				return nil, err
			}
			if _, err := hsh.Write(data); err != nil {
				return nil, err
			}
		}
	}
	return
}

// Streams the data from the input reader to the cloud.
func Upload(client secret.Transport, token auth.SignedToken, w BlockWriter, data io.Reader, o ...func(*StreamOptions)) (digest []byte, num int, err error) {
	opts := BuildStreamOptions(o...)

	hsh := opts.Strength.Hash().New()
	defer func() {
		digest = hsh.Sum(nil)
	}()

	done, blocks := make(chan error), make(chan secret.Block)
	go func() {
		defer close(blocks)

		total, buf := 0, make([]byte, opts.BlockSize)
		for {

			n, err := io.ReadFull(data, buf)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				err = nil
			}
			if err != nil {
				done <- err
				return
			}
			if n == 0 {
				done <- nil
				return
			}

			block, err := w.Write(buf[:n])
			if err != nil {
				done <- err
				return
			}

			if _, err := hsh.Write(buf[:n]); err != nil {
				done <- err
				return
			}

			total += n
			if total > MaxBytes {
				done <- errors.Wrapf(ErrMaxSizeExceeded, "Secrets must be less than 1MB")
				return
			}

			select {
			case <-opts.Canceler:
				return
			case blocks <- block:
			}
		}
	}()

	upload := func(batch []secret.Block) error {
		defer func() {
			num += len(batch)
		}()

		return client.SaveBlocks(token, batch...)
	}

	var batch []secret.Block
	for {
		select {
		case <-opts.Canceler:
			return
		case b := <-blocks:
			batch = append(batch, b)
			if len(batch) < int(opts.BatchSize) {
				continue
			}

			if err = upload(batch); err != nil {
				return
			}

			batch = nil
		case err = <-done:
			if err != nil || len(batch) == 0 {
				return
			}

			err = upload(batch)
			return
		}
	}
	return
}

type BlockWriterFn func([]byte) (secret.Block, error)

func (b BlockWriterFn) Write(in []byte) (secret.Block, error) {
	return b(in)
}

type BlockReaderFn func(secret.Block) ([]byte, error)

func (b BlockReaderFn) Read(in secret.Block) ([]byte, error) {
	return b(in)
}

// Returns a new block reader that generates a series of ordered,
// byte segments. The reader does NOT perform error tracking.
func NewBlockReader(salt crypto.Salt, pass []byte, cipher crypto.Cipher) BlockReader {
	key := salt.Apply(pass, cipher.KeySize())
	return BlockReaderFn(func(b secret.Block) ([]byte, error) {
		return b.Decrypt(key)
	})
}

// Returns a new block writer that generates a series of ordered,
// indexed blocks. The writer does NO error tracking.  All calls,
// other than via their indexes are independent of each other.
func NewBlockWriter(rand io.Reader, orgId, streamId uuid.UUID, salt crypto.Salt, pass []byte, cipher crypto.Cipher) BlockWriter {
	idx, key := 0, salt.Apply(pass, cipher.KeySize())
	return BlockWriterFn(func(data []byte) (next secret.Block, err error) {
		defer func() {
			idx++
		}()

		ct, err := cipher.Apply(rand, key, data)
		if err != nil {
			return
		}

		next = secret.Block{orgId, streamId, idx, ct}
		return
	})
}
