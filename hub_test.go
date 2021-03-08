package mercure

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	testAddr        = "127.0.0.1:4242"
	testMetricsAddr = "127.0.0.1:4243"
)

func TestNewHub(t *testing.T) {
	h := createDummy()

	assert.IsType(t, &viper.Viper{}, h.config)
}

func TestNewHubWithConfig(t *testing.T) {
	h, err := NewHub(
		WithPublisherJWT([]byte("foo"), jwa.HS256.String()),
		WithSubscriberJWT([]byte("bar"), jwa.HS256.String()),
	)
	require.NotNil(t, h)
	require.Nil(t, err)
}

func TestNewHubValidationError(t *testing.T) {
	assert.Panics(t, func() {
		NewHubFromViper(viper.New())
	})
}

func TestNewHubTransportValidationError(t *testing.T) {
	v := viper.New()
	v.Set("publisher_jwt_key", "foo")
	v.Set("jwt_key", "bar")
	v.Set("transport_url", "foo://")

	assert.Panics(t, func() {
		NewHubFromViper(viper.New())
	})
}

func TestStartCrash(t *testing.T) {
	if os.Getenv("BE_START_CRASH") == "1" {
		Start()

		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStartCrash") //nolint:gosec
	cmd.Env = append(os.Environ(), "BE_START_CRASH=1")
	err := cmd.Run()

	var e *exec.ExitError
	require.True(t, errors.As(err, &e))
	assert.False(t, e.Success())
}

func createDummy(options ...Option) *Hub {
	tss, _ := NewTopicSelectorStore(0, 0)
	options = append(
		[]Option{
			WithPublisherJWT([]byte("publisher"), jwa.HS256.String()),
			WithSubscriberJWT([]byte("subscriber"), jwa.HS256.String()),
			WithLogger(zap.NewNop()),
			WithTopicSelectorStore(tss),
		},
		options...,
	)

	h, _ := NewHub(options...)
	h.config = viper.New()
	h.config.Set("addr", testAddr)
	h.config.Set("metrics_addr", testMetricsAddr)

	return h
}

func createAnonymousDummy(options ...Option) *Hub {
	options = append(
		[]Option{WithAnonymous()},
		options...,
	)

	return createDummy(options...)
}

func createDummyAuthorizedJWT(h *Hub, r role, topics []string) string {
	token := jwt.New()

	var keyConfig *jwtKey
	switch r {
	case rolePublisher:
		token.Set("mercure", mercureClaim{Publish: topics})
		keyConfig = h.publisherJWT.singleKeyConfig

	case roleSubscriber:
		var payload struct {
			Foo string `json:"foo"`
		}
		payload.Foo = "bar"
		token.Set("mercure", mercureClaim{
			Subscribe: topics,
			Payload:   payload,
		})

		keyConfig = h.subscriberJWT.singleKeyConfig
	}

	tokenString, _ := jwt.Sign(token, keyConfig.signingMethod, keyConfig.key)

	return string(tokenString)
}

func createDummyUnauthorizedJWT() string {
	token := jwt.New()
	tokenString, _ := jwt.Sign(token, jwa.HS256, []byte("unauthorized"))

	return string(tokenString)
}

func createDummyNoneSignedJWT() string {
	return "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwiaWF0IjoxNTczMzU4Mzk2fQ."
}
