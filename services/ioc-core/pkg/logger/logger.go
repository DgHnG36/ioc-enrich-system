package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

type Fields map[string]interface{}

var defaultLogger *Logger

func Init() {
	defaultLogger = New()
}

func New() *Logger {
	log := logrus.New()

	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "msg",
		},
	})
	return &Logger{Logger: log}
}

// Init Logger with other config
func NewWithConfig(level string, format string, output io.Writer) *Logger {
	log := logrus.New()

	// Set output
	if output != nil {
		log.SetOutput(output)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	log.SetLevel(logLevel)

	// Set formatter
	if format == "text" {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	} else {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	}
	return &Logger{Logger: log}
}

func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	return l.Logger.WithContext(ctx)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...Fields) {
	entry := l.Logger.WithFields(MergeFields(fields...))
	entry.Info(msg)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...Fields) {
	entry := l.Logger.WithFields(MergeFields(fields...))
	entry.Debug(msg)
}

// Warn logs a warn message
func (l *Logger) Warn(msg string, fields ...Fields) {
	entry := l.Logger.WithFields(MergeFields(fields...))
	entry.Warn(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields ...Fields) {
	f := MergeFields(fields...)
	if err != nil {
		f["error"] = err.Error()
	}
	entry := l.Logger.WithFields(f)
	entry.Error(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, err error, fields ...Fields) {
	f := MergeFields(fields...)
	if err != nil {
		f["error"] = err.Error()
	}
	entry := l.Logger.WithFields(f)
	entry.Fatal(msg)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(msg string, err error, fields ...Fields) {
	f := MergeFields(fields...)
	if err != nil {
		f["error"] = err.Error()
	}
	entry := l.Logger.WithFields(f)
	entry.Panic(msg)
}

// LogGRPCRequest logs gRPC request
func (l *Logger) LogRPCRequest(method string, fields Fields) {
	f := Fields{
		"type":   "grpc_request",
		"method": method,
	}
	for k, v := range fields {
		f[k] = v
	}
	l.Logger.Info("gRPC received", f)
}

// LogRPCResponse logs gRPC response
func (l *Logger) LogRPCResponse(method string, duration time.Duration, fields Fields) {
	f := Fields{
		"type":        "grpc_response",
		"method":      method,
		"duration_ms": duration.Milliseconds(),
	}
	for k, v := range fields {
		f[k] = v
	}
	l.Logger.Info("gRPC sent", f)
}

// LogHTTPRequest logs HTTP request
func (l *Logger) LogHTTPRequest(method string, path string, fields Fields) {
	f := Fields{
		"type":   "http_request",
		"method": method,
		"path":   path,
	}
	for k, v := range fields {
		f[k] = v
	}
	l.Logger.Info("HTTP request received", f)
}

// LogHTTPResponse logs HTTP response
func (l *Logger) LogHTTPResponse(method string, path string, status_code int, duration time.Duration, fields Fields) {
	f := Fields{
		"type":        "http_response",
		"method":      method,
		"path":        path,
		"status":      status_code,
		"duration_ms": duration.Milliseconds(),
	}
	for k, v := range fields {
		f[k] = v
	}
	l.Logger.Info("HTTP response sent", f)
}

func MergeFields(fields ...Fields) logrus.Fields {
	result := logrus.Fields{}
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}

func GetDefault() *Logger {
	return defaultLogger
}

func SetDefault(logger *Logger) {
	defaultLogger = logger
}

// Global functions using default logger

func Info(msg string, fields ...Fields) {
	defaultLogger.Info(msg, fields...)
}

func Debug(msg string, fields ...Fields) {
	defaultLogger.Debug(msg, fields...)
}

func Warn(msg string, fields ...Fields) {
	defaultLogger.Warn(msg, fields...)
}

func Error(msg string, err error, fields ...Fields) {
	defaultLogger.Error(msg, err, fields...)
}

func Fatal(msg string, err error, fields ...Fields) {
	defaultLogger.Fatal(msg, err, fields...)
}

func Panic(msg string, err error, fields ...Fields) {
	defaultLogger.Panic(msg, err, fields...)
}
