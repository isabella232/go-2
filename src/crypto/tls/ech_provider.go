package tls

import (
	"crypto/tls/internal/hpke"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const (
	maxConfigIdLen = 255
)

// ECHProvider specifies the interface of an ECH service provider that decrypts
// the ECH payload on behalf of the client-facing server. It also defines the
// set of acceptable ECH configurations.
type ECHProvider interface {
	// GetContext attempts to construct the HPKE context used by the
	// client-facing server for decryption. (See draft-irtf-cfrg-hpke-05,
	// Section 5.2.)
	//
	// handle encodes the parameters of the client's "encrypted_client_hello"
	// extension that are needed to construct the context. In
	// draft-ietf-tls-esni-08, these are the ECH cipher suite, the identity of
	// the ECH configuration, and the encapsulated key.
	//
	// hrrPsk is the PSK used to construct the context. This is set by the
	// caller in case the server previously sent a HelloRetryRequest in this
	// connection. Otherwise, len(hrrPsk) == 0.
	//
	// version is the version of ECH indicated by the client.
	//
	// res.Status == ECHProviderStatusSuccess indicates the call was successful
	// and the caller may proceed. res.Context is set.
	//
	// res.Status == ECHProviderStatusReject indicates the caller must reject
	// ECH. res.RetryConfigs may be set.
	//
	// res.Status == ECHProviderStatusAbort indicates the caller must abort the
	// handshake. res.Alert and res.Error are set.
	GetContext(handle, hrrPsk []byte, version uint16) (res ECHProviderResult)
}

// ECHProviderStatus is the status of the ECH provider's response.
type ECHProviderStatus uint

const (
	ECHProviderSuccess ECHProviderStatus = 0
	ECHProviderReject                    = 1
	ECHProviderAbort                     = 2
)

// ECHProviderResult represents the result of invoking the ECH provider.
type ECHProviderResult struct {
	Status ECHProviderStatus

	// Alert is the TLS alert sent by the caller when aborting the handshake.
	Alert uint8

	// Error is the error propagated by the caller when aborting the handshake.
	Error error

	// RetryConfigs is the sequence of ECH configs to offer to the client for
	// retrying the handshake. This may be set in case of success or rejection.
	RetryConfigs []byte

	// Context is the server's HPKE context. This is set if ECH is not rejected
	// by the provider and no error was reported. The data has the following
	// format (in TLS syntax):
	//
	// enum { sender(0), receiver(1) } HpkeRole;
	//
	// struct {
	//     HpkeRole role;
	//     HpkeKemId kem_id;   // as defined in draft-irtf-cfrg-hpke-05
	//     HpkeKdfId kdf_id;   // as defined in draft-irtf-cfrg-hpke-05
	//     HpkeAeadId aead_id; // as defined in draft-irtf-cfrg-hpke-05
	//     opaque exporter_secret<0..255>;
	//     opaque key<0..255>;
	//     opaque nonce<0..255>;
	//     uint64 seq;
	// } HpkeContext;
	//
	// NOTE(cjpatton): This format is specified neither in the ECH spec nor the
	// HPKE spec. It is the format chosen for the HPKE implementation that we're
	// using. See
	// https://github.com/cisco/go-hpke/blob/9e7d3e90b7c3a5b08f3099c49520c587568c77d6/hpke.go#L198
	Context []byte
}

// EXP_ECHKeySet implements the ECHProvider interface for a sequence of ECH keys.
type EXP_ECHKeySet struct {
	// The serialized ECHConfigs, in order of the server's preference.
	configs []byte

	// Maps a configuration identifier to its secret key.
	sk map[[maxConfigIdLen + 1]byte]EXP_ECHKey
}

// EXP_NewECHKeySet constructs an EXP_ECHKeySet.
func EXP_NewECHKeySet(keys []EXP_ECHKey) (*EXP_ECHKeySet, error) {
	keySet := new(EXP_ECHKeySet)
	keySet.sk = make(map[[maxConfigIdLen + 1]byte]EXP_ECHKey)
	configs := make([]byte, 0)
	for _, key := range keys {
		// Compute the set of KDF algorithms supported by this configuration.
		kdfIds := make(map[uint16]bool)
		for _, suite := range key.config.suites {
			kdfIds[suite.kdfId] = true
		}

		// Compute the configuration identifier for each KDF.
		for kdfId, _ := range kdfIds {
			kdf, err := echCreateHpkeKdf(kdfId)
			if err != nil {
				return nil, err
			}
			configId := kdf.Expand(kdf.Extract(nil, key.config.raw), []byte(echHpkeInfoConfigId), kdf.OutputSize())
			var b cryptobyte.Builder
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(configId)
			})
			var id [maxConfigIdLen + 1]byte // Initialized to zero
			copy(id[:], b.BytesOrPanic())
			keySet.sk[id] = key
		}

		configs = append(configs, key.config.raw...)
	}

	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(configs)
	})
	keySet.configs = b.BytesOrPanic()

	return keySet, nil
}

// GetContext is required by the ECHProvider interface.
func (keySet *EXP_ECHKeySet) GetContext(rawHandle, hrrPsk []byte, version uint16) (res ECHProviderResult) {
	// Ensure we know how to proceed. Currently only draft-ietf-tls-esni-08 is
	// supported.
	if version != extensionECH {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = errors.New("version not supported")
		return // Abort
	}

	// Parse the handle.
	s := cryptobyte.String(rawHandle)
	handle := new(echContextHandle)
	if !echReadContextHandle(&s, handle) || !s.Empty() {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("error parsing context handle")
		return // Abort
	}
	handle.raw = rawHandle

	// Look up the secret key for the configuration indicated by the client.
	var id [maxConfigIdLen + 1]byte // Initialized to zero
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.configId)
	})
	copy(id[:], b.BytesOrPanic())
	key, ok := keySet.sk[id]
	if !ok {
		res.Status = ECHProviderReject
		res.RetryConfigs = keySet.configs
		return // Reject
	}

	// Ensure that support for the selected ciphersuite is indicated by the
	// configuration.
	suite := handle.suite
	if !key.config.isPeerCipherSuiteSupported(suite) {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("peer cipher suite is not supported")
		return // Abort
	}

	// Ensure the version indicated by the client matches the version supported
	// by the configuration.
	if version != key.config.version {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertIllegalParameter)
		res.Error = errors.New("peer version not supported")
		return // Abort
	}

	// Compute the decryption context.
	context, err := key.setupServerContext(handle.enc, hrrPsk, suite)
	if err != nil {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = err
		return // Abort
	}

	// Serialize the decryption context.
	res.Context, err = context.marshalServer()
	if err != nil {
		res.Status = ECHProviderAbort
		res.Alert = uint8(alertInternalError)
		res.Error = err
		return // Abort
	}

	res.Status = ECHProviderSuccess
	// Send retry configs just in case the caller needs to reject.
	res.RetryConfigs = keySet.configs
	return // May accept
}

// EXP_ECHKey represents an ECH key and its corresponding configuration. The
// encoding of an ECH Key has following structure (in TLS syntax):
//
// struct {
//     opaque private_key<0..2^16-1>
//     uint16 length<0..2^16-1> // length of config
//     ECHConfig config;        // as defined in draft-ietf-tls-esni-08
// } ECHKey;
//
// NOTE(cjpatton): This format is not specified in the ECH draft.
type EXP_ECHKey struct {
	config ECHConfig
	sk     hpke.KEMPrivateKey
}

// EXP_UnmarshalECHKeys parses a sequence of ECH keys.
func EXP_UnmarshalECHKeys(raw []byte) ([]EXP_ECHKey, error) {
	s := cryptobyte.String(raw)
	keys := make([]EXP_ECHKey, 0)
	var key EXP_ECHKey
	for !s.Empty() {
		var rawSecretKey, rawConfig cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&rawSecretKey) ||
			!s.ReadUint16LengthPrefixed(&rawConfig) {
			return nil, fmt.Errorf("error parsing key")
		}
		config, err := echUnmarshalConfig(rawConfig)
		if err != nil {
			if err == echUnrecognizedVersionError {
				// Skip config with unrecognized version.
				continue
			}
			return nil, err
		}
		key.config = *config
		key.sk, err = echUnmarshalHpkeSecretKey(rawSecretKey, key.config.kemId)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// setupServerContext computes the HPKE context used by the server in the ECH
// extension. If hrrPsk is set, then "SetupPSKR()" is used to generate the
// context. Otherwise, "SetupBaseR()" is used. (See irtf-cfrg-hpke-05 for
// details.)
func (key *EXP_ECHKey) setupServerContext(enc, hrrPsk []byte, suite echCipherSuite) (*echContext, error) {
	hpkeSuite, err := hpkeAssembleCipherSuite(key.config.kemId, suite.kdfId, suite.aeadId)
	if err != nil {
		return nil, err
	}

	info := append(append([]byte(echHpkeInfoSetup), 0), key.config.raw...)
	var decryptechContext *hpke.DecryptContext
	if hrrPsk != nil {
		decryptechContext, err = hpke.SetupPSKR(hpkeSuite, key.sk, enc, hrrPsk, []byte(echHpkeHrrKeyId), info)
		if err != nil {
			return nil, err
		}
	} else {
		decryptechContext, err = hpke.SetupBaseR(hpkeSuite, key.sk, enc, info)
		if err != nil {
			return nil, err
		}
	}
	return &echContext{nil, decryptechContext, false, hpkeSuite}, nil
}
