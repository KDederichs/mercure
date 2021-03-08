package mercure

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"net/http"
	"net/url"
)

// claims contains Mercure's JWT claims.
type claims struct {
	Mercure mercureClaim `json:"mercure"`
	// Optional fallback
	MercureNamespaced *mercureClaim `json:"https://mercure.rocks/"`
}

type mercureClaim struct {
	Publish   []string    `json:"publish"`
	Subscribe []string    `json:"subscribe"`
	Payload   interface{} `json:"payload"`
}

type role int

const (
	roleSubscriber role = iota
	rolePublisher
)

var (
	// ErrInvalidAuthorizationHeader is returned when the Authorization header is invalid.
	ErrInvalidAuthorizationHeader = errors.New(`invalid "Authorization" HTTP header`)
	// ErrNoOrigin is returned when the cookie authorization mechanism is used and no Origin nor Referer headers are presents.
	ErrNoOrigin = errors.New(`an "Origin" or a "Referer" HTTP header must be present to use the cookie-based authorization mechanism`)
	// ErrOriginNotAllowed is returned when the Origin is not allowed to post updates.
	ErrOriginNotAllowed = errors.New("origin not allowed to post updates")
	// ErrUnexpectedSigningMethod is returned when the signing JWT method is not supported.
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	// ErrPublicKey is returned when there is an error with the public key.
	ErrNoneNotSupported    = errors.New("failed to verify jws signature: failed to create verifier: unsupported signature algorithm \"none\"")
	ErrPublicKey           = errors.New("public key error")
	ErrInvalidMode         = errors.New("invalid jwt mode")
	ErrMissingSingleConfig = errors.New("missing single mode configuration")
	ErrMissingKey          = errors.New("key is missing")
)

//
//func getKeySet(jwtConfig *jwtConfig) (jwk.Set, error) {
//	var keyset jwk.Set
//	keyset = jwk.NewSet()
//	switch jwtConfig.mode {
//	case Single:
//		if jwtConfig.singleKeyConfig == nil {
//			return nil, ErrMissingSingleConfig
//		}
//		key, err :=jwk.ParseKey(jwtConfig.singleKeyConfig.key, jwk.WithPEM(true))
//		if err != nil {
//			println("osudjfhNsdokjgfhbdsfapohjusdafgoijhdsfgojjiodfsgajiopjdsfgiojiojpdgfsouijhdfs")
//			panic(fmt.Errorf("%w", err))
//		}
//		publicKey, err := jwk.New(key)
//		if err != nil {
//			return nil, err
//		}
//		keyset.Add(byte)
//		return keyset, nil
//	case Jwk:
//		return nil, ErrInvalidMode
//	default:
//		return nil, ErrInvalidMode
//	}
//}

// Authorize validates the JWT that may be provided through an "Authorization" HTTP header or a "mercureAuthorization" cookie.
// It returns the claims contained in the token if it exists and is valid, nil if no token is provided (anonymous mode), and an error if the token is not valid.
func authorize(r *http.Request, jwtConfig *jwtConfig, publishOrigins []string) (*mercureClaim, error) {
	authorizationHeaders, headerExists := r.Header["Authorization"]
	jwt.RegisterCustomField("mercure", mercureClaim{})
	jwt.RegisterCustomField("https://mercure.rocks/", mercureClaim{})
	//keyset, err := getKeySet(jwtConfig)

	//if err != nil {
	//	// Anonymous
	//	return nil, err
	//}

	if headerExists {
		if len(authorizationHeaders) != 1 || len(authorizationHeaders[0]) < 48 || authorizationHeaders[0][:7] != "Bearer " {
			return nil, ErrInvalidAuthorizationHeader
		}

		return validateJWT(authorizationHeaders[0][7:], jwtConfig)
	}

	cookie, err := r.Cookie("mercureAuthorization")
	if err != nil {
		// Anonymous
		return nil, nil
	}

	// CSRF attacks cannot occur when using safe methods
	if r.Method != "POST" {
		return validateJWT(cookie.Value, jwtConfig)
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// Try to extract the origin from the Referer, or return an error
		referer := r.Header.Get("Referer")
		if referer == "" {
			return nil, ErrNoOrigin
		}

		u, err := url.Parse(referer)
		if err != nil {
			return nil, fmt.Errorf("unable to parse referer: %w", err)
		}

		origin = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	for _, allowedOrigin := range publishOrigins {
		if allowedOrigin == "*" || origin == allowedOrigin {
			return validateJWT(cookie.Value, jwtConfig)
		}
	}

	return nil, fmt.Errorf("%q: %w", origin, ErrOriginNotAllowed)
}

// validateJWT validates that the provided JWT token is a valid Mercure token.
func validateJWT(encodedToken string, jwtConfig *jwtConfig) (*mercureClaim, error) {

	token, err := parseSingle(encodedToken, jwtConfig)

	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT: %w", err)
	}

	possibleClaim, ok := token.Get("mercure")
	if !ok {
		possibleClaim, ok = token.Get("https://mercure.rocks/")
		if !ok {
			return &mercureClaim{
				Publish:   nil,
				Subscribe: nil,
			}, nil
		}
	}

	switch claim := possibleClaim.(type) {
	case mercureClaim:
		return &claim, nil
	default:
		return &mercureClaim{
			Publish:   nil,
			Subscribe: nil,
		}, nil
	}
}

func parseSingle(encodedToken string, jwtConfig *jwtConfig) (jwt.Token, error) {
	switch jwtConfig.singleKeyConfig.signingMethod.String() {
	case jwa.NoSignature.String():
		return nil, ErrNoneNotSupported
	case jwa.HS256.String(), jwa.HS512.String(), jwa.HS384.String():
		return jwt.Parse([]byte(encodedToken), jwt.WithVerify(jwtConfig.singleKeyConfig.signingMethod, jwtConfig.singleKeyConfig.key), jwt.WithValidate(true))
	default:
		key, err := jwk.ParseKey(jwtConfig.singleKeyConfig.key, jwk.WithPEM(true))
		if err != nil {
			return nil, err
		}
		return jwt.Parse([]byte(encodedToken), jwt.WithVerify(jwtConfig.singleKeyConfig.signingMethod, key), jwt.WithValidate(true))
	}
}

func canReceive(s *TopicSelectorStore, topics, topicSelectors []string) bool {
	for _, topic := range topics {
		for _, topicSelector := range topicSelectors {
			if s.match(topic, topicSelector) {
				return true
			}
		}
	}

	return false
}

func canDispatch(s *TopicSelectorStore, topics, topicSelectors []string) bool {
	for _, topic := range topics {
		var matched bool
		for _, topicSelector := range topicSelectors {
			if topicSelector == "*" {
				return true
			}

			if s.match(topic, topicSelector) {
				matched = true

				break
			}
		}

		if !matched {
			return false
		}
	}

	return true
}
