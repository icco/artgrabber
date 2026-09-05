package db

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/icco/gutil/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm/logger"
)

// newTestLogger returns a GormLogger plus a context carrying the same observed
// logger. Trace prefers the request-scoped logger from ctx, so the context has
// to be wired up or the assertions watch the wrong sink.
func newTestLogger(t *testing.T, level logger.LogLevel) (*GormLogger, context.Context, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	base := zap.New(core)
	l := NewGormLogger(base).LogMode(level).(*GormLogger)

	var ctx context.Context
	h := logging.InjectLogger(base.Sugar())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	return l, ctx, logs
}

func fc() func() (string, int64) {
	return func() (string, int64) { return "SELECT 1", 1 }
}

func TestTraceDoesNotLogEveryQueryByDefault(t *testing.T) {
	// The whole point: one line per query filled the host's shared journal.
	l, ctx, logs := newTestLogger(t, logger.Warn)
	l.Trace(ctx, time.Now(), fc(), nil)
	if got := logs.Len(); got != 0 {
		t.Fatalf("expected no output at warn level, got %d entries: %v", got, logs.All())
	}
}

func TestTraceLogsQueriesAtInfoLevel(t *testing.T) {
	l, ctx, logs := newTestLogger(t, logger.Info)
	l.Trace(ctx, time.Now(), fc(), nil)
	if got := logs.FilterMessage("GORM query").Len(); got != 1 {
		t.Fatalf("expected the query logged at info level, got %d", got)
	}
}

func TestTraceAlwaysLogsErrors(t *testing.T) {
	// An error has to survive any level a caller might pick, short of silent.
	for _, level := range []logger.LogLevel{logger.Error, logger.Warn, logger.Info} {
		l, ctx, logs := newTestLogger(t, level)
		l.Trace(ctx, time.Now(), fc(), errors.New("boom"))
		if got := logs.FilterMessage("GORM error").Len(); got != 1 {
			t.Fatalf("level %v: expected the error logged, got %d", level, got)
		}
	}
}

func TestTraceSilentSuppressesEvenErrors(t *testing.T) {
	l, ctx, logs := newTestLogger(t, logger.Silent)
	l.Trace(ctx, time.Now(), fc(), errors.New("boom"))
	if got := logs.Len(); got != 0 {
		t.Fatalf("expected silence, got %d entries", got)
	}
}

func TestTraceLogsSlowQueriesWithoutPerQueryLogging(t *testing.T) {
	// Slow statements are the signal worth keeping once the firehose is off.
	l, ctx, logs := newTestLogger(t, logger.Warn)
	l.Trace(ctx, time.Now().Add(-2*slowQueryThreshold), fc(), nil)
	if got := logs.FilterMessage("GORM slow query").Len(); got != 1 {
		t.Fatalf("expected the slow query logged, got %d entries: %v", got, logs.All())
	}
}

func TestLogModeReturnsACopy(t *testing.T) {
	// Returning the receiver made the level unsettable, which is how the
	// per-query logging became impossible to turn off.
	l, _, _ := newTestLogger(t, logger.Warn)
	other := l.LogMode(logger.Info).(*GormLogger)
	if l.level != logger.Warn {
		t.Fatalf("LogMode mutated the receiver: level is now %v", l.level)
	}
	if other.level != logger.Info {
		t.Fatalf("LogMode returned the wrong level: %v", other.level)
	}
}

func TestLevelFromEnv(t *testing.T) {
	cases := []struct {
		in   string
		want logger.LogLevel
	}{
		{"silent", logger.Silent},
		{"error", logger.Error},
		{"warn", logger.Warn},
		{"INFO", logger.Info},
		{" info ", logger.Info}, // padded: the value is trimmed before matching
		{"", logger.Warn},
		{"bogus", logger.Warn},
	}
	for _, c := range cases {
		t.Setenv("GORM_LOG_LEVEL", c.in)
		if got := levelFromEnv(); got != c.want {
			t.Errorf("GORM_LOG_LEVEL=%q: got %v, want %v", c.in, got, c.want)
		}
	}
}
