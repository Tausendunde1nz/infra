# Commercial S11.2-R15.18.2 activation-relative timer contract

## Scope and observed failure

R15.18.2 corrects only the S11 controller timer's first-run clock and its
immediate post-arm acceptance.  R15.18.1 performed one explicit timer
`StartUnit`, but the live timer still became `active/elapsed`, exposed no
finite next event and produced no PID 1 controller invocation.  The canonical
rollback completed once and left the S11 units absent.

The target runs systemd 255.  In that version, `OnBootSec` is based on the
machine boot timestamp, `OnActiveSec` is based on activation of the timer unit,
and `OnUnitActiveSec` is based on activation of the triggered service.  A
missed `OnBootSec` event on a genuinely fresh timer is immediately due; a
blanket claim that every late-installed `OnBootSec` timer becomes elapsed is
therefore false.

The matching live/source classification is
`BOOT_RELATIVE_ONE_SHOT_DISABLED_BY_REUSED_MANAGER_TRIGGER_STATE`.  systemd
255 disables an already elapsed `TIMER_BOOT` expression when a last-trigger
marker is present.  If the triggered unit has no usable deployment-local
activation base, `TIMER_UNIT_ACTIVE` contributes no event, leaving no timer
expression to schedule.  This explains the observed elapsed/infinite state
without weakening the natural-run proof.

Authoritative semantics are documented in the systemd 255 timer manual and
implemented in `src/core/timer.c`:

- <https://github.com/systemd/systemd/blob/v255/man/systemd.timer.xml>
- <https://github.com/systemd/systemd/blob/v255/src/core/timer.c>
- <https://github.com/systemd/systemd/blob/v255/man/systemd.unit.xml>

## Corrected contract

The first deadline is now `OnActiveSec=3min`; `OnBootSec` is absent.  A deploy
on a long-running host therefore schedules against the current timer
activation, independent of host uptime or inherited boot-relative state.  At
normal boot, timers.target activates the timer and the same three-minute delay
is measured from that activation, preserving the intended boot behavior.

`OnUnitActiveSec=5min` remains the recurring clock.  After the first natural
timer-triggered service run succeeds, the next observation is derived from
that service activation.  `RandomizedDelaySec=30s` and `AccuracySec=15s`
remain unchanged.  `Persistent=true` is retained as harmless compatibility;
systemd documents persistence as meaningful for `OnCalendar` timers, not for
these monotonic expressions.

`RefuseManualStart=yes` remains mandatory.  Timer dependency activation is
allowed by systemd while an explicit manual service start remains denied.

## Immediate and final acceptance

The arm helper still issues exactly one timer start.  During a bounded
five-read window immediately afterward it now requires all of:

- enabled;
- `ActiveState=active`;
- `SubState=waiting`;
- a finite future realtime or monotonic next event.

Failure returns `S11_2_CONTROLLER_TIMER_INITIAL_SCHEDULE_RED` immediately;
there is no retry and no natural-run timeout wait.  This early state is only a
necessary condition.  Final handoff still requires a new trigger after the
deployment marker, a new PID 1 timer-created InvocationID, successful service
completion, and a finite recurring activation afterward.

The deterministic A-M matrix covers the rejected old live state, fresh and
reused manager state, long-running-host activation, boot activation, the first
natural run, recurrence, elapsed/infinite early failures, service failure,
historical/manual invocation rejection, one-arm enforcement, and already
enabled timer activation.  It performs no runtime mutation.

## Freeze and product boundaries

The replacement freeze is
`s11-2-r15-18-2-activation-relative-timer-freeze-r1` with the same 29 canonical
ordered bindings.  All prior tags remain immutable.  Real AVS, adult media,
adult submission, community adult media, external publishing, payments,
controlled beta and production remain closed.
