package pulsarClient

import (
	"log"
)

// ANSI color codes
const (
	ColorReset = "\033[0m"
	ColorCyan  = "\033[36m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
)

// PulsarLogInfo prints a formatted log message in cyan.
func PulsarLogInfo(format string, v ...interface{}) {
	log.Printf(ColorCyan+"[Pulsar] "+format+ColorReset, v...)
}

// PulsarLogSuccess prints a formatted log message in green.
func PulsarLogSuccess(format string, v ...interface{}) {
	log.Printf(ColorGreen+"[Pulsar] "+format+ColorReset, v...)
}

// PulsarLogError prints a formatted log message in red.
func PulsarLogError(format string, v ...interface{}) {
	log.Printf(ColorRed+"[Pulsar] "+format+ColorReset, v...)
}
