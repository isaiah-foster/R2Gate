// Package verr separates verification failures from operational errors.
//
// A Failure means the log served something that does not verify: a bad signature, a tile or entry
// bundle that does not match the signed tree, a checkpoint that is not consistent with an earlier
// one. That is evidence of misbehaviour (or corruption) and the CLI exits 1. Anything else, such
// as a network error or an HTTP 404, means verification could not be done, and the CLI exits 4.
package verr

import (
	"errors"
	"fmt"
)

// Failure is a verification failure: the log's data is wrong, not merely unavailable.
type Failure struct {
	Err error
}

func (f *Failure) Error() string { return "verification failed: " + f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

// Failf returns a Failure with a formatted message.
func Failf(format string, args ...any) error {
	return &Failure{Err: fmt.Errorf(format, args...)}
}

// Fail wraps err as a Failure, unless it is nil or already one.
func Fail(err error) error {
	if err == nil || IsFailure(err) {
		return err
	}
	return &Failure{Err: err}
}

// IsFailure reports whether err is, or wraps, a Failure.
func IsFailure(err error) bool {
	var f *Failure
	return errors.As(err, &f)
}
