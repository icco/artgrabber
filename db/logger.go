package db

import (
	"context"
	"time"

	"github.com/icco/gutil/logging"
	"go.uber.org/zap"
	"gorm.io/gorm/logger"
)

// GormLogger implements gorm's logger.Interface and forwards records to zap.
// When a request-scoped logger is attached to ctx via gutil/logging it is
// preferred; otherwise we fall back to the package-level logger captured at
// construction time.
type GormLogger struct {
	logger *zap.SugaredLogger
}

// NewGormLogger creates a new GORM logger that forwards to zap.
func NewGormLogger(base *zap.Logger) *GormLogger {
	return &GormLogger{logger: base.Sugar()}
}

// LogMode is part of gorm's logger.Interface; zap controls leveling so we
// just return the receiver unchanged.
func (l *GormLogger) LogMode(level logger.LogLevel) logger.Interface {
	return l
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
	l.loggerFor(ctx).Infow(msg, "data", data)
}

// Warn logs warning messages.
func (l *GormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	l.loggerFor(ctx).Warnw(msg, "data", data)
}

// Error logs error messages.
func (l *GormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	l.loggerFor(ctx).Errorw(msg, "data", data)
}

// Trace logs SQL query execution at debug level (or error level on failure).
func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	elapsed := time.Since(begin)
	sql, rows := fc()
	scoped := l.loggerFor(ctx)

	if err != nil {
		scoped.Errorw("GORM error",
			zap.Error(err),
			"sql", sql,
			"rows", rows,
			"elapsed", elapsed,
		)
		return
	}

	scoped.Debugw("GORM query",
		"sql", sql,
		"rows", rows,
		"elapsed", elapsed,
	)
}
