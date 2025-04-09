package common

import (
	"github.com/sirupsen/logrus"
)

// Interface
type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

// Adaptateur
type logrusAdapter struct {
	base *logrus.Logger
}

func (l *logrusAdapter) Debug(a ...interface{})            { l.base.Debug(a...) }
func (l *logrusAdapter) Debugf(f string, a ...interface{}) { l.base.Debugf(f, a...) }
func (l *logrusAdapter) Info(a ...interface{})             { l.base.Info(a...) }
func (l *logrusAdapter) Infof(f string, a ...interface{})  { l.base.Infof(f, a...) }
func (l *logrusAdapter) Warn(a ...interface{})             { l.base.Warn(a...) }
func (l *logrusAdapter) Warnf(f string, a ...interface{})  { l.base.Warnf(f, a...) }
func (l *logrusAdapter) Error(a ...interface{})            { l.base.Error(a...) }
func (l *logrusAdapter) Errorf(f string, a ...interface{}) { l.base.Errorf(f, a...) }

func FromLogrus(l *logrus.Logger) Logger {
	return &logrusAdapter{base: l}
}
