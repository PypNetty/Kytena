package cli

import (
	"log"
	"os"
)

type defaultLogger struct {
	logger *log.Logger
}

func (l *defaultLogger) Info(msg string, args ...interface{}) {
	l.logger.Printf("INFO: "+msg, args...)
}

func (l *defaultLogger) Error(msg string, args ...interface{}) {
	l.logger.Printf("ERROR: "+msg, args...)
}

func (l *defaultLogger) Debug(msg string, args ...interface{}) {
	l.logger.Printf("DEBUG: "+msg, args...)
}

func (l *defaultLogger) Warn(msg string, args ...interface{}) {
	l.logger.Printf("WARN: "+msg, args...)
}

func (l *defaultLogger) Warnf(format string, args ...interface{}) {
	l.logger.Printf("WARN: "+format, args...)
}

var globalLogger Logger

// GetLogger returns the global logger instance
func GetLogger() Logger {
	if globalLogger == nil {
		globalLogger = &defaultLogger{
			logger: log.New(os.Stdout, "", log.LstdFlags),
		}
	}
	return globalLogger
}

// SetLogger allows setting a custom logger implementation
func SetLogger(logger Logger) {
	globalLogger = logger
}
