package mercure

import (
	"errors"
	"fmt"
	"github.com/form3tech-oss/jwt-go"
	"net/http"
	"net/url"
)

// claims contains Mercure's JWT claims.
type claims struct {
	Mercure mercureClaim `json:"mercure"`
	// Optional fallback
	MercureNamespaced *mercureClaim `json:"https://mercure.rocks/"`
	jwt.StandardClaims
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
	// ErrInvalidJWT is returned when the JWT is invalid.
	ErrInvalidJWT = errors.New("invalid JWT")
	// ErrPublicKey is returned when there is an error with the public key.
	ErrPublicKey           = errors.New("public key error")
	ErrInvalidMode         = errors.New("invalid jwt mode")
	ErrMissingSingleConfig = errors.New("missing single mode configuration")
)

func getJwtKey(jwtConfig *jwtConfig) (*jwtKey, error) {
	switch jwtConfig.mode {
	case Single:
		if jwtConfig.singleKeyConfig == nil {
			return nil, ErrMissingSingleConfig
		}
		return jwtConfig.singleKeyConfig, nil
	case Jwk:
		return nil, ErrInvalidMode
	default:
		return nil, ErrInvalidMode
	}
}

// Authorize validates the JWT that may be provided through an "Authorization" HTTP header or a "mercureAuthorization" cookie.
// It returns the claims contained in the token if it exists and is valid, nil if no token is provided (anonymous mode), and an error if the token is not valid.
func authorize(r *http.Request, jwtConfig *jwtConfig, publishOrigins []string) (*claims, error) {
	authorizationHeaders, headerExists := r.Header["Authorization"]

	jwtKeyConfig, err := getJwtKey(jwtConfig)

	if err != nil {
		// Anonymous
		return nil, nil
	}

	if headerExists {
		if len(authorizationHeaders) != 1 || len(authorizationHeaders[0]) < 48 || authorizationHeaders[0][:7] != "Bearer " {
			return nil, ErrInvalidAuthorizationHeader
		}

		return validateJWT(authorizationHeaders[0][7:], jwtKeyConfig)
	}

	cookie, err := r.Cookie("mercureAuthorization")
	if err != nil {
		// Anonymous
		return nil, nil
	}

	// CSRF attacks cannot occur when using safe methods
	if r.Method != "POST" {
		return validateJWT(cookie.Value, jwtKeyConfig)
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
			return validateJWT(cookie.Value, jwtKeyConfig)
		}
	}

	return nil, fmt.Errorf("%q: %w", origin, ErrOriginNotAllowed)
}

// validateJWT validates that the provided JWT token is a valid Mercure token.
func validateJWT(encodedToken string, jwtKey *jwtKey) (*claims, error) {
	token, err := jwt.ParseWithClaims(encodedToken, &claims{}, func(token *jwt.Token) (interface{}, error) {
		switch jwtKey.signingMethod.(type) {
		case *jwt.SigningMethodHMAC:
			return jwtKey.key, nil
		case *jwt.SigningMethodRSA:
			pub, err := jwt.ParseRSAPublicKeyFromPEM(jwtKey.key)
			if err != nil {
				return nil, fmt.Errorf("unable to parse RSA public key: %w", err)
			}

			return pub, nil
		}

		return nil, fmt.Errorf("%T: %w", jwtKey.signingMethod, ErrUnexpectedSigningMethod)
	})
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(*claims); ok && token.Valid {
		if claims.MercureNamespaced != nil {
			claims.Mercure = *claims.MercureNamespaced
		}

		return claims, nil
	}

	return nil, ErrInvalidJWT
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
