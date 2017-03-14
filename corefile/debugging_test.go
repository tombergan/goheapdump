package corefile

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var debugLevel = flag.Int("debuglevel", 0, "debug verbosity level")

func TestMain(m *testing.M) {
	flag.Parse()
	if *debugLevel > 0 {
		DebugLogf = func(verbosityLevel int, format string, args ...interface{}) {
			if verbosityLevel >= *debugLevel {
				fmt.Printf(format+"\n", args...)
			}
		}
	}
	os.Exit(m.Run())
}
