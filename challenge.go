// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// HTTP carrier for CLC-CHALLENGE-v1 (RFC 9457 Problem Details).
//
// A refusal that could be fixed by presenting evidence should say so in a
// machine-readable way: RFC 9457 gives the envelope (application/problem+json
// with type/title/status/detail/instance), and the challenge goes in an
// extension member.  The Authorization Evidence Challenge specification carries
// its challenge the same way over 403, and maps the challenge's retry lower
// bound to the Retry-After header.
//
// The carrier adds nothing to the semantics: the challenge itself is built and
// validated in register/semantics, and it authorizes nothing.

package aicverifier

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/varwof/register/semantics"
)

// ProblemTypeEvidenceRequired identifies this profile's problem type.
const ProblemTypeEvidenceRequired = "https://varwof.com/clc/v1/problems/evidence-required"

// ProblemContentType is the RFC 9457 media type.
const ProblemContentType = "application/problem+json"

// ChallengeCarrier writes the HTTP response for a refusal that carries a
// challenge.  The problem is the machine-readable "what is still needed"; the
// carrier decides how that is conveyed (RFC 9457 problem+json by default, but
// a deployment that routes through an aggregator may want its own shape).  The
// SDK sets Retry-After from the challenge's retry lower bound before calling
// Write, so a non-standard carrier still keeps the bound visible.  The carrier
// owns status, content type and body; Write must be safe for concurrent use.
type ChallengeCarrier interface {
	// Write renders problem as the response body.  The header may be modified
	// before the body is written; returning an error leaves the response
	// partially written and the caller falls back to a minimal JSON error.
	Write(w http.ResponseWriter, problem *ProblemDetails) error
}

// problemJSONCarrier is the built-in RFC 9457 application/problem+json carrier.
type problemJSONCarrier struct{}

func (problemJSONCarrier) Write(w http.ResponseWriter, problem *ProblemDetails) error {
	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(problem.Status)
	body, err := marshalProblem(problem)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// DefaultChallengeCarrier is the problem+json carrier used when a Config does
// not set ChallengeCarrier.
var DefaultChallengeCarrier ChallengeCarrier = problemJSONCarrier{}

// ProblemDetails is an RFC 9457 problem document carrying a CLC challenge.
type ProblemDetails struct {
	Type      string               `json:"type"`
	Title     string               `json:"title,omitempty"`
	Status    int                  `json:"status"`
	Detail    string               `json:"detail,omitempty"`
	Instance  string               `json:"instance,omitempty"`
	Challenge *semantics.Challenge `json:"challenge,omitempty"`
}

// ChallengeConfig controls whether and how refusals carry a challenge.
type ChallengeConfig struct {
	// TTL bounds how long the challenge may drive a retry.
	TTL time.Duration
	// Audience names the relying party the challenge is addressed to.
	Audience string
	// RetryAfter, when set, becomes the challenge's retry lower bound (and the
	// Retry-After header).  It exists because retrying a refusal can amplify
	// load: the client is told when a corrected presentation is welcome.
	RetryAfter time.Duration
	// ObtainHints tell the requester where the missing item can be obtained.
	ObtainHints []semantics.ObtainHint
	// Now, NewID and NewNonce are injectable for tests.  Defaults: time.Now,
	// and 16 random bytes hex-encoded (the nonce must be unpredictable; single
	// use of the retry is the enforcement point's business).
	Now      func() time.Time
	NewID    func() string
	NewNonce func() string
}

func (c ChallengeConfig) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c ChallengeConfig) newID() (string, error)    { return c.randomToken(c.NewID) }
func (c ChallengeConfig) newNonce() (string, error) { return c.randomToken(c.NewNonce) }

// randomToken produces a randomized token (16 random bytes, hex-encoded),
// propagating the error from rand.Read. A challenge token is the enforcement
// point's one-time-use marker: silently returning an empty string on RNG
// failure (previously) turned "randomness unavailable" into a fixed, replayable
// challenge value (M2).
func (c ChallengeConfig) randomToken(override func() string) (string, error) {
	if override != nil {
		return override(), nil
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("challenge: random token: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// buildChallengeForResult returns the challenge for a denial that presenting
// evidence can fix.  A denial with nothing to obtain returns nil, nil: dressing
// a hard refusal as "retry later" would be a lie.
func buildChallengeForResult(res *PipelineResult, cfg ChallengeConfig) (*semantics.Challenge, error) {
	if res == nil {
		return nil, nil
	}
	for _, od := range res.OperationDecisions {
		if od.Verdict != semantics.VerdictAllowUR || od.Released {
			continue
		}
		decision := semantics.Decision{Verdict: semantics.VerdictAllowUR, Unresolved: od.Unresolved}
		actionDigest, err := semantics.DigestOf(semantics.Operation{ID: od.ID, Params: od.Params})
		if err != nil {
			return nil, err
		}
		nonce, err := cfg.newNonce()
		if err != nil {
			return nil, err
		}
		if nonce == "" {
			return nil, fmt.Errorf("challenge nonce unavailable")
		}
		id, err := cfg.newID()
		if err != nil {
			return nil, err
		}
		params := semantics.ChallengeParams{
			ID:           id,
			Nonce:        nonce,
			Audience:     cfg.Audience,
			ActionDigest: actionDigest,
			Now:          cfg.now(),
			TTL:          cfg.TTL,
			ObtainHints:  cfg.ObtainHints,
		}
		if params.ID == "" {
			return nil, fmt.Errorf("challenge id unavailable")
		}
		if cfg.RetryAfter > 0 {
			params.Retry = &semantics.RetryTiming{
				NotBefore: cfg.now().Add(cfg.RetryAfter),
				JitterSec: 0,
			}
		}
		return challengeFromDecision(decision, params)
	}
	return nil, nil
}

func challengeFromDecision(decision semantics.Decision, params semantics.ChallengeParams) (*semantics.Challenge, error) {
	c, err := semantics.BuildChallengeFromDecision(decision, params)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// problemForResult builds the RFC 9457 document for a denied admission, or nil
// when the refusal carries no challenge.
func problemForResult(res *PipelineResult, cfg *ChallengeConfig, detail string) (*ProblemDetails, error) {
	if cfg == nil {
		return nil, nil
	}
	challenge, err := buildChallengeForResult(res, *cfg)
	if err != nil || challenge == nil {
		return nil, err
	}
	return &ProblemDetails{
		Type:      ProblemTypeEvidenceRequired,
		Title:     "Authorization evidence required",
		Status:    http.StatusForbidden,
		Detail:    detail,
		Challenge: challenge,
	}, nil
}

// writeAuthError writes err as a problem document when it carries one, and as
// the SDK's compact JSON error otherwise.  The carrier comes from cfg (nil
// falls back to problem+json).  A challenge's retry lower bound is always
// mapped to Retry-After (RFC 9110) before the carrier runs, so a custom
// carrier cannot drop the bound.
func writeAuthError(w http.ResponseWriter, ae *AuthError, cfg *Config) {
	if ae.Problem == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(ae.Status)
		fmt.Fprintf(w, `{"code":%q,"message":%q}`+"\n", ae.Code.String(), ae.Message)
		return
	}
	if retry := ae.Problem.Challenge; retry != nil && retry.Retry != nil {
		if seconds := int(time.Until(retry.Retry.NotBefore).Seconds() + 0.999); seconds > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
		}
	}
	carrier := DefaultChallengeCarrier
	if cfg != nil && cfg.ChallengeCarrier != nil {
		carrier = cfg.ChallengeCarrier
	}
	if err := carrier.Write(w, ae.Problem); err != nil {
		fmt.Fprintf(w, `{"code":%q}`+"\n", ae.Code.String())
	}
}

// marshalProblem is separated so the carrier keeps one JSON encoding point.
func marshalProblem(p *ProblemDetails) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
