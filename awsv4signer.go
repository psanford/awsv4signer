package awsv4signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/psanford/awsv4signer/internal/awssign"
)

type Signer struct {
	AccessKeyID string
	// SecretAccessKeyHmacSha256 should return a new hash.Hash every time it is called.
	// The key for this hmac must be the string: "AWS4"+SecretAccessKey
	// A common implementation will be to return hmac.New() from this function.
	SecretAccessKeyHmacSha256 func() hash.Hash
	SessionToken              string
}

func (s *Signer) SignSDKRequest(req *request.Request) {
	s.SignSDKRequestWithOpts(req)
}

func (s *Signer) SignSDKRequestWithOpts(req *request.Request, opts ...Option) {
	signOpts := options{
		ts: time.Now(),
	}

	for _, opt := range opts {
		opt.setOption(&signOpts)
	}

	internalSigner := awssign.Signer{
		AccessKeyID:               s.AccessKeyID,
		SecretAccessKeyHmacSha256: s.SecretAccessKeyHmacSha256,
		SessionToken:              s.SessionToken,
	}

	internalSigner.SignRequest(req, signOpts.ts)
}

func (s *Signer) Sign(r *http.Request, body io.ReadSeeker, service, region string, signTime time.Time) (http.Header, error) {
	internalSigner := awssign.Signer{
		AccessKeyID:               s.AccessKeyID,
		SecretAccessKeyHmacSha256: s.SecretAccessKeyHmacSha256,
		SessionToken:              s.SessionToken,
	}

	return internalSigner.SignHTTP(r, body, service, region, 0, false, signTime)
}

func (s *Signer) Presign(r *http.Request, body io.ReadSeeker, service, region string, exp time.Duration, signTime time.Time) (http.Header, error) {
	internalSigner := awssign.Signer{
		AccessKeyID:               s.AccessKeyID,
		SecretAccessKeyHmacSha256: s.SecretAccessKeyHmacSha256,
		SessionToken:              s.SessionToken,
	}

	return internalSigner.SignHTTP(r, body, service, region, exp, true, signTime)
}

type options struct {
	ts time.Time
}

type Option interface {
	setOption(*options) error
}

type timeOpt struct {
	ts time.Time
}

func (o timeOpt) setOption(opts *options) error {
	opts.ts = o.ts
	return nil
}

func StaticAccessKeyHmac(secretAccessKey string) func() hash.Hash {
	return func() hash.Hash {
		return hmac.New(sha256.New, []byte("AWS4"+secretAccessKey))
	}
}
