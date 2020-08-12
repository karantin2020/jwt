/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"errors"
	"fmt"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
	json "gopkg.in/square/go-jose.v2/json"
)

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken struct {
	payload           func(k interface{}) ([]byte, error)
	unverifiedPayload func() []byte
	Headers           []jose.Header
}

// NestedJSONWebToken represents a JSON Web Token (as specified in RFC7519).
type NestedJSONWebToken struct {
	enc     *jose.JSONWebEncryption
	Headers []jose.Header
}

// ErrNoneAlgorithm describes error if jwt has alg==none
var ErrNoneAlgorithm = errors.New("None algorithm is used in jwt header")

// Claims deserializes a JSONWebToken into dest using the provided key.
func (t *JSONWebToken) Claims(key interface{}, dest ...interface{}) error {
	for _, header := range t.Headers {
		switch {
		case header.Algorithm == "None":
		case header.Algorithm == "none":
			return ErrNoneAlgorithm
		}
	}

	payloadKey := tryJWKS(t.Headers, key)

	b, err := t.payload(payloadKey)
	if err != nil {
		return err
	}

	for _, d := range dest {
		if err := json.Unmarshal(b, d); err != nil {
			return err
		}
	}

	return nil
}

// UnsafeClaimsWithoutVerification deserializes the claims of a
// JSONWebToken into the dests. For signed JWTs, the claims are not
// verified. This function won't work for encrypted JWTs.
func (t *JSONWebToken) UnsafeClaimsWithoutVerification(dest ...interface{}) error {
	if t.unverifiedPayload == nil {
		return fmt.Errorf("square/go-jose: Cannot get unverified claims")
	}
	claims := t.unverifiedPayload()
	for _, d := range dest {
		if err := json.Unmarshal(claims, d); err != nil {
			return err
		}
	}
	return nil
}

// Decrypt decrypts encrypted jwt
func (t *NestedJSONWebToken) Decrypt(decryptionKey interface{}) (*JSONWebToken, error) {
	key := tryJWKS(t.Headers, decryptionKey)

	b, err := t.enc.Decrypt(key)
	if err != nil {
		return nil, err
	}

	sig, err := ParseSigned(string(b))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignOpt represents signing options
type SignOpt = jose.SigningKey

// EncOpt represents encryption options
type EncOpt struct {
	ContEnc jose.ContentEncryption
	Rcpt    jose.Recipient
}

type tokenBuilder struct {
	cl  Claims
	sig jose.Signer
	enc jose.Encrypter
}

// ErrNilClaims represents nil value claims error
var ErrNilClaims = errors.New("passed nil claims")

// ErrNilOptions represents nil options error
var ErrNilOptions = errors.New("passed nil options")

// NewWithClaims creates builder for signed or signed-then-encrypted tokens
func NewWithClaims(c Claims, s *SignOpt, e ...*EncOpt) (string, error) {
	if c == nil {
		return "", ErrNilClaims
	}
	if s == nil {
		return "", ErrNilOptions
	}

	var sig jose.Signer
	var enc jose.Encrypter
	var err error

	sig, err = jose.NewSigner(*s, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	if len(e) > 0 {
		enc, err = jose.NewEncrypter(
			e[0].ContEnc,
			e[0].Rcpt,
			(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
		)
		if err != nil {
			return "", err
		}
	}

	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	signed, err := sig.Sign(p)
	if err != nil {
		return "", err
	}

	p2, err := signed.CompactSerialize()
	if err != nil {
		return "", err
	}
	if len(e) == 0 {
		return p2, nil
	}

	encrypted, err := enc.Encrypt([]byte(p2))
	p2, err = encrypted.CompactSerialize()
	if err != nil {
		return "", err
	}

	return p2, nil
}

// ParseSigned parses token from JWS form.
func ParseSigned(s string) (*JSONWebToken, error) {
	sig, err := jose.ParseSigned(s)
	if err != nil {
		return nil, err
	}
	headers := make([]jose.Header, len(sig.Signatures))
	for i, signature := range sig.Signatures {
		headers[i] = signature.Header
	}

	return &JSONWebToken{
		payload:           sig.Verify,
		unverifiedPayload: sig.UnsafePayloadWithoutVerification,
		Headers:           headers,
	}, nil
}

// ParseEncrypted parses token from JWE form.
func ParseEncrypted(s string) (*JSONWebToken, error) {
	enc, err := jose.ParseEncrypted(s)
	if err != nil {
		return nil, err
	}

	return &JSONWebToken{
		payload: enc.Decrypt,
		Headers: []jose.Header{enc.Header},
	}, nil
}

// ParseSignedAndEncrypted parses signed-then-encrypted token from JWE form.
func ParseSignedAndEncrypted(s string) (*NestedJSONWebToken, error) {
	enc, err := jose.ParseEncrypted(s)
	if err != nil {
		return nil, err
	}

	contentType, _ := enc.Header.ExtraHeaders[jose.HeaderContentType].(string)
	if strings.ToUpper(contentType) != "JWT" {
		return nil, ErrInvalidContentType
	}

	return &NestedJSONWebToken{
		enc:     enc,
		Headers: []jose.Header{enc.Header},
	}, nil
}

func tryJWKS(headers []jose.Header, key interface{}) interface{} {
	jwks, ok := key.(*jose.JSONWebKeySet)
	if !ok {
		return key
	}

	var kid string
	for _, header := range headers {
		if header.KeyID != "" {
			kid = header.KeyID
			break
		}
	}

	if kid == "" {
		return key
	}

	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return key
	}

	return keys[0].Key
}
