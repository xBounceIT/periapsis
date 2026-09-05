package ticketing

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TicketExportCSVStats describes the exact bytes written to a temporary
// object. Rows exclude the single header record.
type TicketExportCSVStats struct {
	Rows   uint32
	Bytes  uint64
	Digest [sha256.Size]byte
}

func (stats TicketExportCSVStats) String() string {
	return fmt.Sprintf(
		"TicketExportCSVStats{rows:%d,bytes:%d,digest:[REDACTED]}",
		stats.Rows,
		stats.Bytes,
	)
}

func (stats TicketExportCSVStats) GoString() string { return stats.String() }

// TicketExportCSVEncoder streams one bounded RFC 4180 artifact. It is owned by
// one worker goroutine and deliberately does not close the underlying writer.
// A failed or incomplete stream must remain a temporary object and must never
// be promoted by the storage adapter.
type TicketExportCSVEncoder struct {
	output      *ticketExportCSVOutput
	columns     int
	maximumRows uint32
	rows        uint32
	closed      bool
	failure     error
}

func (encoder TicketExportCSVEncoder) String() string {
	return fmt.Sprintf(
		"TicketExportCSVEncoder{rows:%d,maximum_rows:%d,closed:%t,storage:[REDACTED]}",
		encoder.rows,
		encoder.maximumRows,
		encoder.closed,
	)
}

func (encoder TicketExportCSVEncoder) GoString() string { return encoder.String() }

func NewTicketExportCSVEncoder(
	target io.Writer,
	definition TicketExportDefinition,
	header []string,
) (*TicketExportCSVEncoder, error) {
	if target == nil || !validTicketExportDefinition(definition) ||
		len(header) == 0 || len(header) > TicketExportMaximumColumns ||
		!validTicketExportCSVRecord(header, len(header)) {
		return nil, ErrInvalidTicketExport
	}
	output := &ticketExportCSVOutput{
		target: target, digest: sha256.New(), maximum: definition.maximumBytes,
	}
	if _, err := output.Write(encodeTicketExportCSVRecord(neutralizeTicketExportCSVRecord(header))); err != nil {
		return nil, classifyTicketExportCSVWriteError(err)
	}
	return &TicketExportCSVEncoder{
		output: output, columns: len(header),
		maximumRows: definition.maximumRows,
	}, nil
}

func (encoder *TicketExportCSVEncoder) WriteRow(cells []string) error {
	if encoder == nil || encoder.output == nil ||
		encoder.closed {
		return ErrInvalidTicketExport
	}
	if encoder.failure != nil {
		return encoder.failure
	}
	if !validTicketExportCSVRecord(cells, encoder.columns) {
		encoder.failure = ErrInvalidTicketExport
		return encoder.failure
	}
	if encoder.rows >= encoder.maximumRows {
		encoder.failure = ErrTicketExportOutputLimit
		return encoder.failure
	}
	if _, err := encoder.output.Write(encodeTicketExportCSVRecord(neutralizeTicketExportCSVRecord(cells))); err != nil {
		encoder.failure = classifyTicketExportCSVWriteError(err)
		return encoder.failure
	}
	encoder.rows++
	return nil
}

func (encoder *TicketExportCSVEncoder) Close() (TicketExportCSVStats, error) {
	if encoder == nil || encoder.output == nil || encoder.closed {
		return TicketExportCSVStats{}, ErrInvalidTicketExport
	}
	encoder.closed = true
	if encoder.failure != nil {
		return TicketExportCSVStats{}, encoder.failure
	}
	var digest [sha256.Size]byte
	copy(digest[:], encoder.output.digest.Sum(nil))
	return TicketExportCSVStats{
		Rows: encoder.rows, Bytes: encoder.output.written, Digest: digest,
	}, nil
}

type ticketExportCSVOutput struct {
	target  io.Writer
	digest  hash.Hash
	maximum uint64
	written uint64
}

func (output *ticketExportCSVOutput) Write(value []byte) (int, error) {
	if output == nil || output.target == nil || output.digest == nil {
		return 0, ErrTicketExportWriteFailed
	}
	if uint64(len(value)) > output.maximum-output.written {
		return 0, ErrTicketExportOutputLimit
	}
	written, err := output.target.Write(value)
	if written < 0 || written > len(value) {
		return 0, ErrTicketExportWriteFailed
	}
	if written > 0 {
		_, _ = output.digest.Write(value[:written])
		output.written += uint64(written)
	}
	if err != nil || written != len(value) {
		return written, ErrTicketExportWriteFailed
	}
	return written, nil
}

func validTicketExportCSVRecord(values []string, columns int) bool {
	if len(values) != columns || columns < 1 || columns > TicketExportMaximumColumns {
		return false
	}
	for _, value := range values {
		if len(value) > TicketExportMaximumCellBytes || !utf8.ValidString(value) {
			return false
		}
		for _, character := range value {
			if character == '\n' || character == '\r' || character == '\t' {
				continue
			}
			if unicode.IsControl(character) || ticketExportDirectionalControl(character) {
				return false
			}
		}
	}
	return true
}

func ticketExportDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func neutralizeTicketExportCSVRecord(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = canonicalizeTicketExportCSVCell(value)
	}
	return result
}

func canonicalizeTicketExportCSVCell(value string) string {
	value = neutralizeTicketExportCSVCell(value)
	if strings.ContainsRune(value, '\r') {
		value = strings.ReplaceAll(value, "\r\n", "\n")
		value = strings.ReplaceAll(value, "\r", "\n")
	}
	return value
}

func encodeTicketExportCSVRecord(values []string) []byte {
	var output strings.Builder
	for index, value := range values {
		if index > 0 {
			output.WriteByte(',')
		}
		quoted := strings.ContainsAny(value, ",\"\n") || len(values) == 1 && value == ""
		if !quoted {
			output.WriteString(value)
			continue
		}
		output.WriteByte('"')
		for _, character := range []byte(value) {
			switch character {
			case '"':
				output.WriteString("\"\"")
			case '\n':
				output.WriteString("\r\n")
			default:
				output.WriteByte(character)
			}
		}
		output.WriteByte('"')
	}
	output.WriteString("\r\n")
	return []byte(output.String())
}

func neutralizeTicketExportCSVCell(value string) string {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			continue
		}
		if strings.ContainsRune("=+-@", character) {
			return "'" + value
		}
		return value
	}
	return value
}

func classifyTicketExportCSVWriteError(err error) error {
	if errors.Is(err, ErrTicketExportOutputLimit) {
		return ErrTicketExportOutputLimit
	}
	return ErrTicketExportWriteFailed
}
