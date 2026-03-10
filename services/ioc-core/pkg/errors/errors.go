package errors

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	CodeNotFound           = "NOT_FOUND"
	CodeAlreadyExists      = "ALREADY_EXISTS"
	CodeInvalidInput       = "INVALID_INPUT"
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeRateLimited        = "RATE_LIMITED"
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	CodeInternalError      = "INTERNAL_ERROR"
	CodeTimeout            = "TIMEOUT"
	CodeConflict           = "CONFLICT"
	CodeInvalidConfig      = "INVALID_CONFIG"
)

type AppError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	HTTPStatus int                    `json:"-"`
	GRPCStatus codes.Code             `json:"-"`
}

// Assertion
func (e *AppError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Resolve race logic
func (e *AppError) Clone() *AppError {
	c := *e
	if e.Details != nil {
		c.Details = make(map[string]interface{}, len(e.Details))
		for k, v := range e.Details {
			c.Details[k] = v
		}
	}
	return &c
}

// Custom AppError
func (e *AppError) WithMessage(msg string) *AppError {
	e.Message = msg
	return e
}

func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details = details
	return e
}

func (e *AppError) ToGRPCError() error {
	return status.Error(e.GRPCStatus, e.Message)
}

var (
	ErrNotFound = &AppError{
		Code:       CodeNotFound,
		Message:    "Resource not found",
		HTTPStatus: http.StatusNotFound,
		GRPCStatus: codes.NotFound,
	}

	ErrAlreadyExists = &AppError{
		Code:       CodeAlreadyExists,
		Message:    "Resource already exists",
		HTTPStatus: http.StatusConflict,
		GRPCStatus: codes.AlreadyExists,
	}

	ErrInvalidInput = &AppError{
		Code:       CodeInvalidInput,
		Message:    "Invalid input",
		HTTPStatus: http.StatusBadRequest,
		GRPCStatus: codes.InvalidArgument,
	}

	ErrUnauthorized = &AppError{
		Code:       CodeUnauthorized,
		Message:    "Unauthorized",
		HTTPStatus: http.StatusUnauthorized,
		GRPCStatus: codes.Unauthenticated,
	}

	ErrForbidden = &AppError{
		Code:       CodeForbidden,
		Message:    "Forbidden",
		HTTPStatus: http.StatusForbidden,
		GRPCStatus: codes.PermissionDenied,
	}

	ErrRateLimited = &AppError{
		Code:       CodeRateLimited,
		Message:    "Rate limited exceeded",
		HTTPStatus: http.StatusTooManyRequests,
		GRPCStatus: codes.ResourceExhausted,
	}

	ErrServiceUnavailable = &AppError{
		Code:       CodeServiceUnavailable,
		Message:    "Service unavailable",
		HTTPStatus: http.StatusServiceUnavailable,
		GRPCStatus: codes.Unavailable,
	}

	ErrInternal = &AppError{
		Code:       CodeInternalError,
		Message:    "Internal server error",
		HTTPStatus: http.StatusInternalServerError,
		GRPCStatus: codes.Internal,
	}

	ErrTimeout = &AppError{
		Code:       CodeTimeout,
		Message:    "Request timeout",
		HTTPStatus: http.StatusRequestTimeout,
		GRPCStatus: codes.DeadlineExceeded,
	}

	ErrConflict = &AppError{
		Code:       CodeConflict,
		Message:    "Resource conflict",
		HTTPStatus: http.StatusConflict,
		GRPCStatus: codes.Aborted,
	}

	ErrInvalidConfig = &AppError{
		Code:       CodeInvalidConfig,
		Message:    "Invalid variables config",
		HTTPStatus: http.StatusInternalServerError,
		GRPCStatus: codes.Internal,
	}
)

func NewError(code, message string, http_status int, grpc_status codes.Code) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Details:    make(map[string]interface{}),
		HTTPStatus: http_status,
		GRPCStatus: grpc_status,
	}
}

func WrapError(err error, code, message string) *AppError {
	appErr, ok := err.(*AppError)
	if ok {
		return appErr.Clone().WithMessage(message)
	}

	return &AppError{
		Code:       code,
		Message:    fmt.Sprintf("%s: %v", message, err),
		HTTPStatus: http.StatusInternalServerError,
		GRPCStatus: codes.Internal,
		Details:    map[string]interface{}{"original_error": err.Error()},
	}
}

func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

func GetHTTPStatus(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

func GetGRPCStatus(err error) codes.Code {
	if appErr, ok := err.(*AppError); ok {
		return appErr.GRPCStatus
	}
	return codes.Internal
}
