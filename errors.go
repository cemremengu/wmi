package wmi

import (
	"errors"
	"fmt"
)

// Error represents a WMI or RPC error with an associated status code.
type Error struct {
	Code uint32
	Op   string
	Msg  string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Op == "" {
		return fmt.Sprintf("%s (0x%08x)", e.Msg, e.Code)
	}
	return fmt.Sprintf("%s: %s (0x%08x)", e.Op, e.Msg, e.Code)
}

func codedError(code uint32, lookup map[uint32]string, fallback string) error {
	msg := lookup[code]
	if msg == "" {
		msg = fallback
	}
	return &Error{Code: code, Msg: msg}
}

func wbemError(code uint32) error {
	return codedError(code, wbemErrorMessages, "WBEM_E_UNKNOWN")
}

func rpcError(code uint32) error {
	return codedError(code, rpcErrorMessages, "unknown rpc exception")
}

var rpcBindNakStatusMessages = map[uint32]string{
	rpcAccessDenied:  "ERROR_ACCESS_DENIED",
	rpcAuthnLevelLow: "RPC_S_AUTHN_LEVEL_LOW",
	rpcProtseqDenied: "RPC_S_PROTSEQ_NOT_SUPPORTED",
	rpcSWrongAuth:    "RPC_S_WRONG_KIND_OF_AUTH",
}

func bindNakError(reason uint16, status uint32) error {
	reasonText := map[uint16]string{
		rpcBindNakReasonNotSpecified:               "REASON_NOT_SPECIFIED",
		rpcBindNakReasonTemporaryCongestion:        "TEMPORARY_CONGESTION",
		rpcBindNakReasonLocalLimitExceeded:         "LOCAL_LIMIT_EXCEEDED",
		rpcBindNakReasonProtocolVersionUnsupported: "PROTOCOL_VERSION_NOT_SUPPORTED",
		rpcBindNakReasonAuthTypeUnsupported:        "AUTHENTICATION_TYPE_NOT_SUPPORTED",
		rpcBindNakReasonInvalidAuthInstance:        "INVALID_AUTH_INSTANCE",
	}[reason]
	if reasonText == "" {
		reasonText = fmt.Sprintf("UNKNOWN_REASON_%d", reason)
	}
	statusMsg := rpcBindNakStatusMessages[status]
	if statusMsg == "" {
		statusErr := rpcError(status)
		var re *Error
		if errors.As(statusErr, &re) {
			statusMsg = re.Msg
		}
	}
	if statusMsg != "" {
		return &Error{
			Code: status,
			Op:   "RPC bind rejected",
			Msg:  fmt.Sprintf("%s: %s", reasonText, statusMsg),
		}
	}
	return &Error{
		Code: status,
		Op:   "RPC bind rejected",
		Msg:  reasonText,
	}
}

func isErrorCode(err error, code uint32) bool {
	var coded *Error
	return errors.As(err, &coded) && coded.Code == code
}

// Sentinel errors.
var (
	ErrServerNotOptimized = &Error{Msg: "server does not support smart enumeration"}
	ErrLegacyEncoding     = &Error{Msg: "legacy object encoding is not supported"}
	ErrNotImplemented     = &Error{Msg: "not implemented"}
)
