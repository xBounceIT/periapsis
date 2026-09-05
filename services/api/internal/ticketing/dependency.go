package ticketing

import "reflect"

// nilTicketingDependency closes the typed-nil interface trap at constructor
// boundaries. Dependencies are long-lived process objects, so accepting a
// typed nil would otherwise defer a deterministic panic until the first call.
func nilTicketingDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
