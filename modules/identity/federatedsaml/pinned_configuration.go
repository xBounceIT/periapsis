package federatedsaml

import "time"

// ValidatePinnedConfiguration proves that a configuration is the exact
// normalized snapshot selected by transaction pins. It is intended for the
// application consumer's final pre-commit check; it performs no I/O.
func ValidatePinnedConfiguration(
	configuration Configuration,
	pins TransactionPins,
	observedAt time.Time,
) error {
	if !validInstant(observedAt) || !validTransactionPins(pins) {
		return ErrInvalidConfiguration
	}
	normalized, digest, err := normalizeConfiguration(configuration, observedAt, DefaultLimits())
	if err != nil || !samePins(transactionPins(normalized, digest), pins) {
		return ErrInvalidConfiguration
	}
	return nil
}
