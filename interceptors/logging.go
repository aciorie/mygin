package interceptors

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// InterceptorLogger adapts zap logger to interceptor logger.
// This adapts zap logger to the logging middleware's expected interface.
func InterceptorLogger(l *zap.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		// Convert logging fields to zap fields
		zapFields := make([]zap.Field, 0, len(fields)/2)
		for i := 0; i < len(fields); i += 2 {
			// Ensure we don't panic if fields has odd number of elements.
			if i+1 >= len(fields) {
				break
			}
			key, ok := fields[i].(string)
			if !ok {
				// Skip if key is not a string
				continue
			}
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}

		// Log based on level
		switch lvl {
		case logging.LevelDebug:
			l.Debug(msg, zapFields...)
		case logging.LevelInfo:
			l.Info(msg, zapFields...)
		case logging.LevelWarn:
			l.Warn(msg, zapFields...)
		case logging.LevelError:
			l.Error(msg, zapFields...)
		default:
			l.Error("Unknown log level in interceptor", zap.String("original_msg", msg), zap.Any("level", lvl))
		}
	})
}

// ZapLoggingInterceptor returns a new unary server interceptor that logs requests using Zap.
func ZapLoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	// Configure the logging middleware options
	opts := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall), // Log start and finish
		logging.WithDurationField(logging.DurationToDurationField),     // Use zap.Duration field type
		logging.WithFieldsFromContext(func(ctx context.Context) logging.Fields {
			// Example: Extract trace ID if available in context
			// if span := trace.SpanFromContext(ctx); span != nil {
			// 	return logging.Fields{"traceID", span.SpanContext().TraceID().String()}
			// }
			return nil
		}),
		// Add custom logic to decide what fields to log based on the error
		logging.WithLevels(logging.DefaultServerCodeToLevel), // Default gRPC code to log level mapping
		// logging.WithStatusReasonFieldName("grpc.reason"),     // Log the reason field from status if present
	}

	// Return the interceptor using the adapted logger and options
	return logging.UnaryServerInterceptor(InterceptorLogger(logger), opts...)
}
