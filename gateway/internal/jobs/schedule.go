// Package jobs runs tasks once per period: on a single gateway once for
// that gateway, on a node of a group once for the group (the group's side
// is cluster.Node.Jobs). A feature names a task, says when it is due and
// what to do; it never asks whether there is a group.
package jobs

import (
	"errors"
	"time"
)

// Schedule says when a task is due. Either Every is set (an interval since
// the period before), or Daily (a time of day, on every day or on one day
// of the week, in a named time zone). The zero Schedule is never due: a
// task that is switched off.
type Schedule struct {
	// Every: the task is due when this long has passed since the period
	// before, and at once when it never ran.
	Every time.Duration

	// Daily: the task is due at Hour:Minute local time of Zone.
	Daily        bool
	Hour, Minute int
	// Weekday limits Daily to one day of the week; nil: every day.
	Weekday *time.Weekday
	// Zone is an IANA name ("Europe/Berlin"); "": UTC.
	Zone string

	// MaxLate bounds how late a Daily period may still start or go on
	// (no node was up, or the run before failed); 0: until the next
	// occurrence. A period that is older is left out, never made up.
	MaxLate time.Duration
	// Grace is how long a run may be silent before it counts as broken off
	// and is taken up again (by this node after a failure, by the next
	// keeper after a takeover); 0: DefaultGrace. Bounded to MinGrace and
	// MaxGrace.
	Grace time.Duration
}

// Bounds of a task.
const (
	DefaultGrace = 2 * time.Minute
	MinGrace     = 5 * time.Second
	MaxGrace     = time.Hour
	// MaxItems bounds the items a run may note as done.
	MaxItems = 256
	// MaxName bounds a task's name, so the ids derived from it fit the 64
	// characters of a job record.
	MaxName = 40
)

// ErrSchedule is a schedule that cannot be read.
var ErrSchedule = errors.New("jobs: schedule not valid")

func (s Schedule) off() bool { return s.Every <= 0 && !s.Daily }

func (s Schedule) check() error {
	if s.off() {
		return nil
	}
	if s.Every > 0 && s.Daily {
		return ErrSchedule
	}
	if s.Daily {
		if s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 {
			return ErrSchedule
		}
		if s.Weekday != nil && (*s.Weekday < time.Sunday || *s.Weekday > time.Saturday) {
			return ErrSchedule
		}
		if _, err := s.location(); err != nil {
			return ErrSchedule
		}
	}
	return nil
}

func (s Schedule) location() (*time.Location, error) {
	if s.Zone == "" {
		return time.UTC, nil
	}
	return time.LoadLocation(s.Zone)
}

func (s Schedule) grace() time.Duration {
	g := s.Grace
	if g <= 0 {
		g = DefaultGrace
	}
	return min(max(g, MinGrace), MaxGrace)
}

// nominal is the usual distance between two periods.
func (s Schedule) nominal() time.Duration {
	switch {
	case s.Every > 0:
		return s.Every
	case s.Weekday != nil:
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// occurrence returns the instant at which hour:minute falls on the calendar
// day y-mo-d in loc. A time that does not exist on that day (the clock is
// put forward over it) falls on the next minute that exists; a time that
// exists twice (the clock is put back over it) falls on the first of the
// two.
func occurrence(y int, mo time.Month, d, hour, minute int, loc *time.Location) time.Time {
	t := time.Date(y, mo, d, hour, minute, 0, 0, loc)
	same := func(x time.Time) bool {
		x = x.In(loc)
		return x.Year() == y && x.Month() == mo && x.Day() == d && x.Hour() == hour && x.Minute() == minute
	}
	if same(t) {
		// Twice on this day: the earlier one is up to two hours before.
		for _, back := range []time.Duration{2 * time.Hour, time.Hour, 30 * time.Minute} {
			if e := t.Add(-back); same(e) {
				return e
			}
		}
		return t
	}
	// It does not exist: the first minute of that day at or after it.
	want := hour*60 + minute
	for x := t.Add(-3 * time.Hour).Truncate(time.Minute); x.Before(t.Add(3 * time.Hour)); x = x.Add(time.Minute) {
		l := x.In(loc)
		if l.Year() == y && l.Month() == mo && l.Day() == d && l.Hour()*60+l.Minute() >= want {
			return x
		}
	}
	return t
}

// latest returns the last occurrence of a Daily schedule at or before now;
// zero: none within the last eight days (never, for a valid schedule).
func (s Schedule) latest(now time.Time) time.Time {
	loc, err := s.location()
	if err != nil {
		return time.Time{}
	}
	day := now.In(loc)
	for i := 0; i <= 8; i++ {
		c := day.AddDate(0, 0, -i)
		if s.Weekday != nil && c.Weekday() != *s.Weekday {
			continue
		}
		if t := occurrence(c.Year(), c.Month(), c.Day(), s.Hour, s.Minute, loc); !t.After(now) {
			return t.UTC()
		}
	}
	return time.Time{}
}
