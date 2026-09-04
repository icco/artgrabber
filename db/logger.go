// Package db provides database helpers, including a GORM logger that bridges
// GORM's logger.Interface to the project's zap logging stack.
package db

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/icco/gutil/logging"
	"go.uber.org/zap"
	"gorm.io/gorm/logger"
)

// slowQueryThreshold is the point at which a query is worth a line even when
// per-query logging is off.
const slowQueryThreshold = 500 * time.Millisecond

// GormLogger implements gorm's logger.Interface and forwards records to zap.
// When a request-scoped logger is attached to ctx via gutil/logging it is
// preferred; otherwise we fall back to the package-level logger captured at
// construction time.
type GormLogger struct {
	logger *zap.SugaredLogger
	level  logger.LogLevel
}

// NewGormLogger creates a new GORM logger that forwards to zap.
//
// Level comes from GORM_LOG_LEVEL (silent|error|warn|info), defaulting to
// warn. It used to log every statement unconditionally: at ~340k lines/hour
// that filled the host's shared journal and pushed every other service's
// retention down to a few hours. Set it to info only while debugging.
func NewGormLogger(base *zap.Logger) *GormLogger {
	return &GormLogger{logger: base.Sugar(), level: levelFromEnv()}
}

func levelFromEnv() logger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GORM_LOG_LEVEL"))) {
	case "silent":
		return logger.Silent
	case "error":
		return logger.Error
	case "info":
		return logger.Info
	default:
		return logger.Warn
	}
}

// LogMode returns a copy at the requested level, as gorm's interface expects.
// Returning the receiver unchanged made the level unsettable by any caller.
func (l *GormLogger) LogMode(level logger.LogLevel) logger.Interface {
	cp := *l
	cp.level = level
	return &cp
}

func (l *GormLogger) loggerFor(ctx context.Context) *zap.SugaredLogger {
	if ctx == nil {
		return l.logger
	}
	if scoped := logging.FromContext(ctx); scoped != nil {
		return scoped
	}
	return l.logger
}

// Info logs informational messages.
func (l *GormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if l.level < logger.Info {
		return
	}
	l.loggerFor(ctx).Infow(msg, "data", data)
}

// Warn logs warning messages.
func (l *GormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if l.level < logger.Warn {
		return
	}
	l.loggerFor(ctx).Warnw(msg, "data", data)
}

// Error logs error messages.
func (l *GormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if l.level < logger.Error {
		return
	}
	l.loggerFor(ctx).Errorw(msg, "data", data)
}

// Trace logs failed and slow statements always; every other statement only at
// info level, because one line per query is far too much for a service that
// polls on a timer.
func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	elapsed := time.Since(begin)
	sql, rows := fc()
	scoped := l.loggerFor(ctx)

	if err != nil {
		if l.level < logger.Error {
			return
		}
		scoped.Errorw("GORM error",
			zap.Error(err),
			"sql", sql,
			"rows", rows,
			"elapsed", elapsed,
		)
		return
	}

	if elapsed >= slowQueryThreshold && l.level >= logger.Warn {
		scoped.Warnw("GORM slow query",
			"sql", sql,
			"rows", rows,
			"elapsed", elapsed,
			"threshold", slowQueryThreshold,
		)
		return
	}

	if l.level < logger.Info {
		return
	}

	scoped.Debugw("GORM query",
		"sql", sql,
		"rows", rows,
		"elapsed", elapsed,
	)
}
