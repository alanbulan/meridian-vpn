# Connection failure classification

`core.Snapshot.Failure` is a bounded `FailureKind` value, separate from lifecycle
state and user-facing text. Zero (`FailureNone`) means no failure is recorded.
Unannotated failures are classified only by the engine's trusted lifecycle
phase: backend start, readiness, or connection lost. Raw error strings are never
parsed to guess authentication, certificate, or transport outcomes.

Trusted adapters may return `NewConnectionError` with authentication, trust,
configuration, or transport classifications. This type stores only a validated
numeric enum, has fixed messages, and does not retain or unwrap a raw cause.
Unknown/invalid codes normalize to `FailureUnknown`. NetworkManager now reports locally observed unavailable capability, invalid
configuration, backend-start, readiness and established-connection-loss facts.
An unsuccessful OpenConnect command or malformed authentication result remains
unknown unless a trusted helper supplies a structured classification. The
adapter cannot distinguish password rejection, certificate rejection and
transport failure from a generic command failure. No existing production
adapter currently supplies a trusted transient-transport reason. Error wrappers may themselves contain
secrets, so the engine exposes only the classification, never wrapper text.
Unavailable capability messages are likewise replaced with a static message at
the engine boundary.

Cleanup uncertainty takes precedence over every other failure, including joined
errors and cancellation, and leaves `CleanupFailed` quarantined. Joined typed
failures are independent of their ordering: trust, authentication, configuration,
backend unavailability, unknown and lifecycle failures all precede transport.
A transport label therefore cannot hide a more restrictive known failure. Successful
user-requested cancellation records no failure. Each newly authorized attempt
clears the previous classification; preflight validation/admission rejections do
not overwrite an active attempt's result.

The desktop only offers its one-time, delayed fresh-authentication reminder for
established connection loss or a typed transport failure after successful
cleanup. Other failures show fixed classified text without inviting another
sign-in. The ordinary manual connection action remains available after confirmed
cleanup, with fresh credentials and network authorization required. Changing the
selected session gateway clears password, PSK, key passphrase/PIN, network
authorization and proxy consent before the new target can be connected.

Reminder evidence is bound to `Snapshot.AttemptID`, a process-local counter that
changes only when the engine admits a new connection attempt. The terminal
snapshot retains its attempt identity. If polling misses an intervening retry,
a prior session's connected observation, delayed reminder or visible reminder
is discarded instead of being attached to the new failure. A later established
session can still produce its own one-time reminder. Profile changes also
invalidate pending reminder evidence. This identity is not persisted and does
not grant retry permission.

The GUI records the exact gateway selected for each admitted attempt separately
from credentials. The loss reminder opens a blank authentication form for that
same gateway, including an explicitly selected backup, and displays its full
configured address. It never silently switches recovery back to the primary
address. If the recorded attempt/profile no longer matches or the gateway has
been removed, recovery stops with a notice; the user can still choose the normal
manual connection action. Submission rechecks the configured target and fresh
network/proxy consent before calling the engine. This target metadata is only
in memory and is neither a saved password nor permission to retry.

These codes are diagnostic groundwork, **not retry permission**. There is no
retryability flag, timer, backoff, automatic reconnect, retained credential, or
new network operation. Future reconnect work still needs explicit authorization,
fresh authentication, verified cleanup and protocol-aware safety decisions.

Tests use in-memory adapters and sessions for phase classification, typed and
wrapped errors, cleanup priority, cancellation, reset and secret redaction. Additional tests exercise fake NetworkManager command outcomes, joined
classifications in both orders, reminder gating and gateway-change consent
reset. They do not activate a real VPN or modify system networking.
