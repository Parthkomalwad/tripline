package bundle

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Parthkomalwad/tripline/internal/floor"
)

// Reason says why a bundle was rejected.
type Reason string

const (
	ReasonMalformed      Reason = "malformed"
	ReasonUnsigned       Reason = "insufficient_signatures"
	ReasonRollback       Reason = "rollback"
	ReasonFloor          Reason = "floor_weakened"
	ReasonEarlyLoosening Reason = "early_loosening"
	ReasonBadTime        Reason = "invalid_time"
)

// RejectError is the typed error that Verify returns.
type RejectError struct {
	Reason Reason
	Detail string
}

func (e *RejectError) Error() string { return string(e.Reason) + ": " + e.Detail }

func reject(r Reason, f string, a ...any) *RejectError {
	return &RejectError{r, fmt.Sprintf(f, a...)}
}

// maxSkew is how far created_at may lie ahead of the local clock.
const maxSkew = 5 * time.Minute

// Verify checks a bundle against the trust file and the applied state
// (nil if none). On success it returns the bundle with Changes set, and with
// Pending set if effective_at is after now. On failure the error is a
// *RejectError.
func Verify(data []byte, trust *Trust, current *Applied, now time.Time) (*Bundle, error) {
	b, err := verify(data, trust, current, now)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func verify(data []byte, trust *Trust, current *Applied, now time.Time) (*Bundle, *RejectError) {
	b, err := Parse(data)
	if err != nil {
		return nil, reject(ReasonMalformed, "%v", err)
	}
	fail := func(r *RejectError) (*Bundle, *RejectError) { return b, r }

	payload, err := b.Payload()
	if err != nil {
		return fail(reject(ReasonMalformed, "%v", err))
	}
	if n := trust.countValid(payload, b.Signatures); n < trust.RequiredSignatures {
		return fail(reject(ReasonUnsigned, "%d valid distinct signatures, need %d", n, trust.RequiredSignatures))
	}
	if b.Version < 1 {
		return fail(reject(ReasonMalformed, "version must be at least 1"))
	}
	switch {
	case b.CreatedAt.IsZero() || b.EffectiveAt.IsZero():
		return fail(reject(ReasonBadTime, "created_at and effective_at are required"))
	case b.EffectiveAt.Before(b.CreatedAt):
		return fail(reject(ReasonBadTime, "effective_at is before created_at"))
	case b.CreatedAt.After(now.Add(maxSkew)):
		return fail(reject(ReasonBadTime, "created_at is in the future"))
	}
	var old []map[string]any
	if current != nil {
		if b.Version <= current.Version {
			return fail(reject(ReasonRollback, "version %d is not above applied version %d", b.Version, current.Version))
		}
		old = current.Rules
	}
	rs, err := b.ParseRules()
	if err != nil {
		return fail(reject(ReasonMalformed, "%v", err))
	}
	if err := floor.Check(rs); err != nil {
		return fail(reject(ReasonFloor, "%v", err))
	}
	// A floor rule that the applied bundle carried must stay in the next one.
	// The compiled-in copy still runs, but dropping it is a weakening attempt.
	for _, f := range floor.Rules() {
		if byID(old)[f.ID] != nil && byID(b.Rules)[f.ID] == nil {
			return fail(reject(ReasonFloor, "floor rule %q removed", f.ID))
		}
	}
	b.Changes = Diff(old, b.Rules)
	if loose := slices.IndexFunc(b.Changes, func(c Change) bool { return c.Dir == Loosen }); loose >= 0 &&
		b.EffectiveAt.Sub(b.CreatedAt) < trust.LooseningDelay {
		return fail(reject(ReasonEarlyLoosening, "%s: %s; effective_at is %s after created_at, policy needs %s",
			b.Changes[loose].RuleID, b.Changes[loose].Detail, b.EffectiveAt.Sub(b.CreatedAt), trust.LooseningDelay))
	}
	b.Pending = b.EffectiveAt.After(now)
	return b, nil
}

// Outcome is the record of one verification, ready for the audit log. The
// watcher appends it as bundle.applied (Accepted) or bundle.rejected. Detail
// holds no rule content or signatures.
type Outcome struct {
	Accepted bool
	Pending  bool // accepted, but takes effect later
	Version  int
	Reason   Reason // empty when accepted
	Detail   string
	Changes  []Change
	// Critical is true for floor weakening, which the spec treats as a
	// critical alert.
	Critical bool
}

// Check runs Verify and returns the bundle and its Outcome. The bundle is nil
// when the outcome is a rejection.
func Check(data []byte, trust *Trust, current *Applied, now time.Time) (*Bundle, Outcome) {
	b, rej := verify(data, trust, current, now)
	o := Outcome{}
	if b != nil {
		o.Version, o.Changes = b.Version, b.Changes
	}
	if rej != nil {
		o.Reason, o.Detail, o.Critical = rej.Reason, rej.Detail, rej.Reason == ReasonFloor
		return nil, o
	}
	o.Accepted, o.Pending = true, b.Pending
	return b, o
}

// AsRejectError returns the typed reason from an error returned by Verify.
func AsRejectError(err error) (*RejectError, bool) {
	var r *RejectError
	return r, errors.As(err, &r)
}
