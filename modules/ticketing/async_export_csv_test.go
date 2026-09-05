package ticketing

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestTicketExportCSVEncoderWritesExactBoundedRFC4180Artifact(t *testing.T) {
	definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
	var output bytes.Buffer
	encoder, err := NewTicketExportCSVEncoder(
		&output,
		definition,
		[]string{"ticket", "title", "note"},
	)
	if err != nil {
		t.Fatal(err)
	}
	rows := [][]string{
		{"ALT-1", "=SUM(A1:A2)", "line one\rline two"},
		{"ALT-2", "'@already-safe", "comma, and \"quote\""},
	}
	for _, row := range rows {
		if err := encoder.WriteRow(row); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := encoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := "ticket,title,note\r\n" +
		"ALT-1,'=SUM(A1:A2),\"line one\r\nline two\"\r\n" +
		"ALT-2,'@already-safe,\"comma, and \"\"quote\"\"\"\r\n"
	if output.String() != want {
		t.Fatalf("CSV output = %q, want %q", output.String(), want)
	}
	digest := sha256.Sum256([]byte(want))
	if stats.Rows != 2 || stats.Bytes != uint64(len(want)) || stats.Digest != digest {
		t.Fatalf("stats=%#v", stats)
	}
	for _, diagnostic := range []string{fmt.Sprintf("%v", stats), fmt.Sprintf("%#v", stats), fmt.Sprintf("%#v", encoder)} {
		if !strings.Contains(diagnostic, "[REDACTED]") || strings.Contains(diagnostic, fmt.Sprint(digest)) {
			t.Fatalf("CSV diagnostic was not redacted: %s", diagnostic)
		}
	}
	if _, err := encoder.Close(); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("second Close() error=%v", err)
	}
}

func TestTicketExportCSVEncoderPoisonsInvalidOrOverLimitStreams(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*TicketExportDefinitionInput)
		header    []string
		rows      [][]string
		want      error
	}{
		{
			name:      "row ceiling",
			configure: func(input *TicketExportDefinitionInput) { input.MaximumRows = 1 },
			header:    []string{"ticket"}, rows: [][]string{{"one"}, {"two"}},
			want: ErrTicketExportOutputLimit,
		},
		{
			name:      "byte ceiling",
			configure: func(input *TicketExportDefinitionInput) { input.MaximumBytes = 10 },
			header:    []string{"ticket"}, rows: [][]string{{"long value"}},
			want: ErrTicketExportOutputLimit,
		},
		{
			name:   "column drift",
			header: []string{"ticket", "state"}, rows: [][]string{{"one"}},
			want: ErrInvalidTicketExport,
		},
		{
			name:   "directional control",
			header: []string{"ticket"}, rows: [][]string{{"safe\u202esecret"}},
			want: ErrInvalidTicketExport,
		},
		{
			name:   "oversized cell",
			header: []string{"ticket"}, rows: [][]string{{strings.Repeat("x", TicketExportMaximumCellBytes+1)}},
			want: ErrInvalidTicketExport,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := ticketExportDefinitionFixture(t, TicketExportAudienceOperator)
			if test.configure != nil {
				test.configure(&input)
			}
			definition, err := NewTicketExportDefinition(input)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			encoder, err := NewTicketExportCSVEncoder(&output, definition, test.header)
			if err != nil {
				t.Fatal(err)
			}
			var writeErr error
			for _, row := range test.rows {
				writeErr = encoder.WriteRow(row)
				if writeErr != nil {
					break
				}
			}
			_, closeErr := encoder.Close()
			if !errors.Is(writeErr, test.want) && !errors.Is(closeErr, test.want) {
				t.Fatalf("WriteRow() error=%v Close() error=%v, want %v", writeErr, closeErr, test.want)
			}
			if uint64(output.Len()) > definition.MaximumBytes() {
				t.Fatalf("temporary output exceeded byte ceiling: %d", output.Len())
			}
		})
	}
}

func TestTicketExportCSVEncoderMapsStorageFailuresAndRejectsUnsafeHeaders(t *testing.T) {
	definition := mustTicketExportDefinition(t, TicketExportAudienceOperator)
	for _, header := range [][]string{
		nil,
		{"safe\x00unsafe"},
		{string([]byte{0xff})},
		make([]string, TicketExportMaximumColumns+1),
	} {
		if _, err := NewTicketExportCSVEncoder(&bytes.Buffer{}, definition, header); !errors.Is(err, ErrInvalidTicketExport) {
			t.Fatalf("unsafe header error=%v", err)
		}
	}
	if _, err := NewTicketExportCSVEncoder(nil, definition, []string{"ticket"}); !errors.Is(err, ErrInvalidTicketExport) {
		t.Fatalf("nil target error=%v", err)
	}

	if _, err := NewTicketExportCSVEncoder(shortTicketExportWriter{}, definition, []string{"ticket"}); !errors.Is(err, ErrTicketExportWriteFailed) {
		t.Fatalf("short storage write error=%v", err)
	}
}

type shortTicketExportWriter struct{}

func (shortTicketExportWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	return len(value) - 1, nil
}

func FuzzTicketExportCSVEncoderStaysBoundedAndFormulaSafe(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain",
		"=HYPERLINK(\"https://example.invalid\")",
		" \t+1+1",
		"line one\r\nline two",
		"\u202esecret",
		string([]byte{0xff}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cell string) {
		input := ticketExportDefinitionFixture(t, TicketExportAudienceOperator)
		input.MaximumRows = 1
		input.MaximumBytes = 256
		definition, err := NewTicketExportDefinition(input)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		encoder, err := NewTicketExportCSVEncoder(&output, definition, []string{"value"})
		if err != nil {
			t.Fatal(err)
		}
		writeErr := encoder.WriteRow([]string{cell})
		stats, closeErr := encoder.Close()
		if output.Len() > int(input.MaximumBytes) {
			t.Fatalf("output grew beyond its hard limit: %d", output.Len())
		}
		if writeErr != nil || closeErr != nil {
			if writeErr == nil && !errors.Is(closeErr, ErrTicketExportOutputLimit) &&
				!errors.Is(closeErr, ErrTicketExportWriteFailed) {
				t.Fatalf("unexpected Close() error=%v", closeErr)
			}
			return
		}
		if stats.Rows != 1 || stats.Bytes != uint64(output.Len()) {
			t.Fatalf("stats=%#v output=%d", stats, output.Len())
		}
		reader := csv.NewReader(strings.NewReader(output.String()))
		records, err := reader.ReadAll()
		if err != nil || len(records) != 2 || len(records[1]) != 1 {
			t.Fatalf("encoded CSV is not readable: records=%#v error=%v", records, err)
		}
		if _, err := reader.Read(); !errors.Is(err, io.EOF) {
			t.Fatalf("reader did not reach EOF: %v", err)
		}
		canonical := canonicalizeTicketExportCSVCell(cell)
		if records[1][0] != canonical {
			t.Fatalf("decoded cell=%q canonical=%q", records[1][0], canonical)
		}
	})
}
