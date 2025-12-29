package consts

import "errors"

const (
	BadClientVersionMessage = "Invalid SSH identification string."
)

var (
	ErrAuthFailed = errors.New("invalid credentials")
)
