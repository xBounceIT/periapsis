package platformlocalaccount

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/argon2"
)

const (
	opaqueTokenBytes = 32
	digestKeyBytes   = 32
)

var localPasswordParams = &argon2id.Params{
	Memory: 64 * 1024, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32,
}

type PasswordHasher interface {
	Hash([]byte) ([]byte, error)
	Verify([]byte, []byte) bool
}

// Argon2idPasswordHasher uses the ADR-0005 memory-hard profile and refuses
// verification parameters that could create a resource-exhaustion primitive.
type Argon2idPasswordHasher struct{}

func (Argon2idPasswordHasher) Hash(password []byte) ([]byte, error) {
	encoded, err := argon2id.CreateHash(string(password), localPasswordParams)
	if err != nil {
		return nil, errors.New("hash local account password")
	}
	result := []byte(encoded)
	if !validGeneratedPasswordPHC(result) {
		clear(result)
		return nil, errors.New("hash local account password")
	}
	return result, nil
}

func (Argon2idPasswordHasher) Verify(password, encoded []byte) bool {
	params, _, _, err := argon2id.DecodeHash(string(encoded))
	if err != nil || !boundedPasswordParams(params) {
		return false
	}
	matched, _, err := argon2id.CheckHash(string(password), string(encoded))
	return err == nil && matched
}

func boundedPasswordParams(params *argon2id.Params) bool {
	return argon2.Version == 0x13 && params != nil &&
		params.Memory >= 19*1024 && params.Memory <= 256*1024 &&
		params.Iterations >= 1 && params.Iterations <= 10 &&
		params.Parallelism >= 1 && params.Parallelism <= 4 &&
		params.SaltLength >= 16 && params.SaltLength <= 64 &&
		params.KeyLength >= 16 && params.KeyLength <= 64
}

func validGeneratedPasswordPHC(encoded []byte) bool {
	if len(encoded) < 32 || len(encoded) > 1024 {
		return false
	}
	params, salt, key, err := argon2id.DecodeHash(string(encoded))
	defer clear(salt)
	defer clear(key)
	if err != nil || params == nil || params.Memory != localPasswordParams.Memory ||
		params.Iterations != localPasswordParams.Iterations || params.Parallelism != localPasswordParams.Parallelism ||
		params.SaltLength != localPasswordParams.SaltLength || params.KeyLength != localPasswordParams.KeyLength {
		return false
	}
	canonical := "$argon2id$v=19$m=65536,t=3,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
	return string(encoded) == canonical
}

type secretGenerator struct {
	random io.Reader
	key    [digestKeyBytes]byte
}

func newSecretGenerator(randomSource io.Reader, key []byte) (secretGenerator, error) {
	if randomSource == nil || len(key) != digestKeyBytes || allZeroBytes(key) {
		return secretGenerator{}, errors.New("local account secret generator requires entropy and a 32-byte key")
	}
	generator := secretGenerator{random: randomSource}
	copy(generator.key[:], key)
	return generator, nil
}

func defaultSecretGenerator(key []byte) (secretGenerator, error) {
	return newSecretGenerator(rand.Reader, key)
}

func (generator secretGenerator) issue(purpose string) ([]byte, [sha256.Size]byte, error) {
	raw := make([]byte, opaqueTokenBytes)
	if _, err := io.ReadFull(generator.random, raw); err != nil {
		clear(raw)
		return nil, [sha256.Size]byte{}, errors.New("generate local account ceremony token")
	}
	if allZeroBytes(raw) {
		clear(raw)
		return nil, [sha256.Size]byte{}, errors.New("generate local account ceremony token")
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	clear(raw)
	digest := generator.digest(purpose, encoded)
	return encoded, digest, nil
}

func (generator secretGenerator) digest(purpose string, values ...[]byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, generator.key[:])
	_, _ = mac.Write([]byte("periapsis/platform-local-account/" + purpose + "/v1"))
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write(value)
	}
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func validOpaqueToken(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(opaqueTokenBytes) || strings.TrimSpace(string(value)) != string(value) {
		return false
	}
	decoded := make([]byte, opaqueTokenBytes)
	written, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	clear(decoded)
	return err == nil && written == opaqueTokenBytes && combined != 0
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
