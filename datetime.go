package wmi

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseWMIDateTime parses a WMI datetime string into a time.Time or time.Duration.
func ParseWMIDateTime(s string) any {
	s = strings.ReplaceAll(s, "*", "0")
	if strings.HasSuffix(s, ":000") {
		days, _ := strconv.Atoi(s[:8])
		hours, _ := strconv.Atoi(s[8:10])
		mins, _ := strconv.Atoi(s[10:12])
		secs, _ := strconv.Atoi(s[12:14])
		micros, _ := strconv.Atoi(s[15:21])
		d := (time.Duration(days) * 24 * time.Hour) +
			(time.Duration(hours) * time.Hour) +
			(time.Duration(mins) * time.Minute) +
			(time.Duration(secs) * time.Second) +
			(time.Duration(micros) * time.Microsecond)
		return d
	}

	if len(s) < 25 {
		return time.Unix(0, 0).UTC()
	}
	for _, idx := range []int{4, 6} {
		if s[idx:idx+2] == "00" {
			s = s[:idx] + "01" + s[idx+2:]
		}
	}
	minutes, err := strconv.Atoi(s[len(s)-3:])
	if err != nil {
		return time.Unix(0, 0).UTC()
	}
	sign := s[len(s)-4]
	hours := minutes / 60
	mins := minutes % 60
	layout := "20060102150405.000000-0700"
	t, err := time.Parse(layout, fmt.Sprintf("%s%c%02d%02d", s[:21], sign, hours, mins))
	if err != nil {
		return time.Unix(0, 0).UTC()
	}
	return t
}

// FormatWMIDateTime formats a time.Time as a WMI datetime string.
func FormatWMIDateTime(t time.Time) string {
	_, offset := t.Zone()
	minutes := offset / 60
	return fmt.Sprintf("%s%+04d", t.Format("2006-01-02 15:04:05"), minutes)
}
