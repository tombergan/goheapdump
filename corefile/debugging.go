package corefile

import "log"

// sanityChecks enables possibly-expensive assertion checks.
// TODO: make this a var, default to false, and set to true in tests
const sanityChecks = true

// DebugLogFn is used to log verbose debugging messages. verbosityLevel is a number
// greater than zero, with higher numbers meaning the message is increasingly verbose.
// If this is nil (the default), then verbose logging is disabled.
var DebugLogf func(verbosityLevel int, format string, args ...interface{})

func printf(format string, args ...interface{}) {
	if DebugLogf != nil {
		DebugLogf(1, format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func logf(format string, args ...interface{}) {
	if DebugLogf != nil {
		DebugLogf(1, format, args...)
	}
}

func verbosef(format string, args ...interface{}) {
	if DebugLogf != nil {
		DebugLogf(2, format, args...)
	}
}
