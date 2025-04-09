package adapters

import (
	"github.com/PypNetty/Kytena/pkg/logger"
	"github.com/sirupsen/logrus"
)

type LogrusAdapter struct {
	Base *logrus.Logger
}

func (l *LogrusAdapter) Debug(args ...interface{})                 { l.Base.Debug(args...) }
func (l *LogrusAdapter) Debugf(format string, args ...interface{}) { l.Base.Debugf(format, args...) }
func (l *LogrusAdapter) Info(args ...interface{})                  { l.Base.Info(args...) }
func (l *LogrusAdapter) Infof(format string, args ...interface{})  { l.Base.Infof(format, args...) }
func (l *LogrusAdapter) Warn(args ...interface{})                  { l.Base.Warn(args...) }
func (l *LogrusAdapter) Warnf(format string, args ...interface{})  { l.Base.Warnf(format, args...) }
func (l *LogrusAdapter) Error(args ...interface{})                 { l.Base.Error(args...) }
func (l *LogrusAdapter) Errorf(format string, args ...interface{}) { l.Base.Errorf(format, args...) }
