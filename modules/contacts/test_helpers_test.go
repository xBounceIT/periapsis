package contacts

import "time"

func testID(seed byte) EntityID {
	var value [16]byte
	for index := range value {
		value[index] = seed + byte(index)
	}
	value[6] = 0x70 | value[6]&0x0f
	value[8] = 0x80 | value[8]&0x3f
	id, err := NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}

func testKey(value string) Key {
	key, err := NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func testEmail(value string) Email {
	email, err := NewEmail(value)
	if err != nil {
		panic(err)
	}
	return email
}

func testInstant(hour int) time.Time {
	return time.Date(2026, time.August, 25, hour, 0, 0, 0, time.UTC)
}

func testFields(email string) ContactFields {
	return ContactFields{
		FirstName:              "Arianna",
		LastName:               "Rossi",
		Email:                  testEmail(email),
		Phone:                  "+390212345678",
		Function:               "Incident manager",
		Language:               "it-IT",
		Timezone:               "Europe/Rome",
		EscalationPriority:     20,
		Class:                  testKey("gold"),
		NotificationCategories: []Key{testKey("comment.public_added"), testKey("sla.warning")},
		EmailAllowed:           true,
		Active:                 true,
		Tags:                   []Key{testKey("executive"), testKey("security")},
	}
}

func testContact(seed byte, tenant EntityID, email string) Contact {
	contact, err := NewContact(testID(seed), tenant, testFields(email), testInstant(8))
	if err != nil {
		panic(err)
	}
	return contact
}
