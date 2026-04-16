package helpers

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

var bootTime time.Time

func init() {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		slog.Warn("Could not get boot time from /proc/stat, timestamps may be shifted")
		bootTime = time.Now()
		return
	}

	// Parse /proc/stat to get boot time
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			secs, _ := strconv.ParseUint(fields[1], 10, 64)
			bootTime = time.Unix(int64(secs), 0)
			return
		}
	}
}

func TimeFromNano(nano uint64) time.Time {
	return time.Unix(0, int64(nano))
}

// As monitor.c uses bpf_ktime_get_ns() which returns nanoseconds since boot, we need to convert it
func KTimeToTime(ktime uint64) time.Time {
	return bootTime.Add(time.Duration(ktime))
}
