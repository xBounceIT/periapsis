package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestColumnMaterializationProducesTypedSortableValuesAndStyles(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	minimum := 75.0
	column, err := NewColumnDefinition(definition, ColumnDefinitionInput{
		ID: fixtureID(170), TenantID: fixtureID(1), Key: mustKey("first_response_consumed"),
		Label: "First response consumed", MetricID: definition.ID(),
		Calculation: ColumnConsumedPercentage, Format: FormatPercentage,
		Sortable: true, Filterable: true, CustomerVisible: true,
		VisibleRoleKeys: []Key{mustKey("analyst"), mustKey("manager")}, Position: 3, Version: 1,
		StyleRules: []ColumnStyleRuleInput{{
			StyleKey: mustKey("danger"), MinimumPercentage: &minimum,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := startedMetricInstance(t, definition)
	at := instance.CreatedAt().Add(3 * time.Hour)
	value, err := MaterializeColumn(column, instance, at, nil)
	wantNextRefresh := at.Add(time.Minute)
	if err != nil || value.Percentage() == nil || *value.Percentage() != 75 ||
		value.StyleKey() != mustKey("danger") || value.NextRefreshAt() == nil ||
		!value.NextRefreshAt().Equal(wantNextRefresh) {
		t.Fatalf("materialized value=%#v error=%v", value, err)
	}
	if !column.VisibleTo(true, nil) || !column.VisibleTo(false, []Key{mustKey("manager")}) ||
		column.VisibleTo(false, []Key{mustKey("viewer")}) {
		t.Fatal("column visibility did not respect customer and role policy")
	}

	percentage := value.Percentage()
	*percentage = 1
	if *value.Percentage() != 75 {
		t.Fatal("materialized percentage getter leaked mutable storage")
	}
	minimum = 5
	value, err = MaterializeColumn(column, instance, at, nil)
	if err != nil || value.StyleKey() != mustKey("danger") {
		t.Fatal("column retained caller-owned style threshold")
	}
}

func TestBusinessClockColumnRefreshesAtNextOpening(t *testing.T) {
	calendar := mustCalendar(t, weekdayCalendarInput())
	input := elapsedMetricInput()
	input.Clock = ClockBusiness
	calendarID := calendar.ID()
	input.CalendarID = &calendarID
	input.CalendarVersion = calendar.Version()
	definition := mustMetricDefinition(t, input)
	column, err := NewColumnDefinition(definition, ColumnDefinitionInput{
		ID: fixtureID(172), TenantID: fixtureID(1), Key: mustKey("business_remaining"),
		Label: "Business remaining", MetricID: definition.ID(),
		Calculation: ColumnRemaining, Format: FormatDuration, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC) // Friday 16:00 CEST.
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: fixtureID(173), SLAInstanceID: fixtureID(174), TenantID: fixtureID(1), ObjectType: ObjectCase,
		ObjectID: fixtureID(175), PolicyID: fixtureID(176), PolicyVersion: 1,
		Definition: definition, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := metricEventForInstance(instance, 177, definition.StartEvent().String(), createdAt)
	instance, changed, err := instance.ApplyEvent(instance.Version(), start, &calendar)
	if err != nil || !changed {
		t.Fatalf("start changed=%t error=%v", changed, err)
	}

	fridayClose := time.Date(2026, 8, 28, 15, 0, 0, 0, time.UTC)
	justBeforeClose := fridayClose.Add(-30 * time.Second)
	value, err := MaterializeColumn(column, instance, justBeforeClose, &calendar)
	if err != nil || value.NextRefreshAt() == nil || !value.NextRefreshAt().Equal(fridayClose) {
		t.Fatalf("open-hours refresh = %v, error=%v; want Friday closing %s", value.NextRefreshAt(), err, fridayClose)
	}
	value, err = MaterializeColumn(column, instance, fridayClose, &calendar)
	mondayOpen := time.Date(2026, 8, 31, 7, 0, 0, 0, time.UTC)
	if err != nil || value.NextRefreshAt() == nil || !value.NextRefreshAt().Equal(mondayOpen) {
		t.Fatalf("Friday-close refresh = %v, error=%v; want Monday opening %s", value.NextRefreshAt(), err, mondayOpen)
	}
}

func TestColumnDefinitionRejectsTypeFormatAndUnsafeVisibilityConfiguration(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	base := ColumnDefinitionInput{
		ID: fixtureID(171), TenantID: fixtureID(1), Key: mustKey("customer_timer_col"), Label: "Sensitive customer timer",
		MetricID: definition.ID(), Calculation: ColumnRemaining, Format: FormatDuration, Version: 1,
	}
	tests := []func(*ColumnDefinitionInput){
		func(input *ColumnDefinitionInput) { input.Format = FormatPercentage },
		func(input *ColumnDefinitionInput) { input.MetricID = fixtureID(199) },
		func(input *ColumnDefinitionInput) {
			input.VisibleRoleKeys = []Key{mustKey("analyst"), mustKey("analyst")}
		},
		func(input *ColumnDefinitionInput) { input.Label = "Private\u202E" },
		func(input *ColumnDefinitionInput) {
			invalid := 101.0
			input.StyleRules = []ColumnStyleRuleInput{{StyleKey: mustKey("danger"), MinimumPercentage: &invalid}}
		},
	}
	for index, mutate := range tests {
		input := base
		mutate(&input)
		if _, err := NewColumnDefinition(definition, input); !errors.Is(err, ErrInvalidMetric) {
			t.Fatalf("invalid column %d error=%v", index, err)
		}
	}

	column, err := NewColumnDefinition(definition, base)
	if err != nil {
		t.Fatal(err)
	}
	foreignInstance := startedMetricInstance(t, definition)
	foreignInstance.tenantID = fixtureID(2)
	if _, err := MaterializeColumn(column, foreignInstance, foreignInstance.UpdatedAt(), nil); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("cross-tenant materialization error=%v", err)
	}
	for _, rendered := range []string{fmt.Sprint(column), fmt.Sprintf("%#v", column)} {
		if strings.Contains(rendered, column.Key().String()) || strings.Contains(rendered, column.Label()) {
			t.Fatalf("column formatting leaked configuration: %q", rendered)
		}
	}
}
