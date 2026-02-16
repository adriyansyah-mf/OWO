// Package logger provides level-based logging (debug, info, warn, error).
package logger

import (
	"log"
	"sync"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	mu    sync.RWMutex
	level Level = LevelInfo
)

func parseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// SetLevel sets the minimum level to log. Default is info.
func SetLevel(s string) {
	mu.Lock()
	defer mu.Unlock()
	level = parseLevel(s)
}

func getLevel() Level {
	mu.RLock()
	defer mu.RUnlock()
	return level
}

func (l Level) enabled(min Level) bool {
	return l >= min
}

// Debug logs if level is debug or lower.
func Debug(format string, v ...interface{}) {
	if getLevel().enabled(LevelDebug) {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info logs if level is info or lower.
func Info(format string, v ...interface{}) {
	if getLevel().enabled(LevelInfo) {
		log.Printf("[INFO] "+format, v...)
	}
}

// Warn logs if level is warn or lower.
func Warn(format string, v ...interface{}) {
	if getLevel().enabled(LevelWarn) {
		log.Printf("[WARN] "+format, v...)
	}
}

// Error logs if level is error (always).
func Error(format string, v ...interface{}) {
	if getLevel().enabled(LevelError) {
		log.Printf("[ERROR] "+format, v...)
	}
}
