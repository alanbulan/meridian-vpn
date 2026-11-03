# Connection failure classification

`core.Snapshot.Failure` is a bounded `FailureKind` value, separate from lifecycle
state and user-facing text. Zero (`FailureNone`) means no failure is recorded.
Unannotated failures are classified only by the engine's trusted lifecycle
phase: backend start, readiness, or connection lost. Raw error strings are never
parsed to guess authentication, certificate, or transport outcomes.

Trusted adapters may return `NewConnectionError` with authentication, trust,
configuration, or transport classifications. This type stores only a validated
numeric enum, has fixed messages, and does not retain or unwrap a raw cause.
Unknown/invalid codes normalize to `FailureUnknown`. Existing adapters do not
suddenly gain protocol-specific classification; they remain phase-classified
until they can provide structured evidence. Error wrappers may themselves contain
secrets, so the engine exposes only the classification, never wrapper text.
Unavailable capability messages are likewise replaced with a static message at
the engine boundary.

Cleanup uncertainty takes precedence over every other failure, including joined
errors and cancellation, and leaves `CleanupFailed` quarantined. Successful
user-requested cancellation records no failure. Each newly authorized attempt
clears the previous classification; preflight validation/admission rejections do
not overwrite an active attempt's result.

These codes are diagnostic groundwork, **not retry permission**. There is no
retryability flag, timer, backoff, automatic reconnect, retained credential, or
new network operation. Future reconnect work still needs explicit authorization,
fresh authentication, verified cleanup and protocol-aware safety decisions.

Tests use in-memory adapters and sessions for phase classification, typed and
wrapped errors, cleanup priority, cancellation, reset and secret redaction. They
do not activate a real VPN or modify system networking.
