package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestDFIRStorageReadNormalizesPostgreSQLInstants(t *testing.T) {
	t.Parallel()
	codec := pgtype.NewMap()
	codec.RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID,
		Codec: &pgtype.TimestamptzCodec{ScanLocation: time.FixedZone("database", 7200)}})
	databaseTime := func(value time.Time) time.Time {
		encoded, err := codec.Encode(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, value, nil)
		if err != nil {
			t.Fatal(err)
		}
		var decoded time.Time
		if err := codec.Scan(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Location() == time.UTC || !decoded.Equal(value) {
			t.Fatal("fixture must preserve the instant in a non-UTC scan location")
		}
		return decoded
	}
	created := alertTestTime(0)
	tenantID, storageID, memberID := alertTestUUID(210), alertTestUUID(211), alertTestUUID(212)
	for _, state := range []kernel.ScanState{kernel.ScanPendingUpload, kernel.ScanAvailable} {
		t.Run(string(state), func(t *testing.T) {
			tx := &dfirTransactionStub{row: func(_ string, args []any, d []any) error {
				if len(args) != 2 || args[0] != tenantID || args[1] != storageID {
					t.Fatal("storage lookup lost its scope")
				}
				*(d[0].(*uuid.UUID)), *(d[1].(*uuid.UUID)) = storageID, tenantID
				*(d[2].(*string)), *(d[3].(*string)) = "periapsis-evidence", tenantID.String()+"/"+storageID.String()
				*(d[4].(*string)), *(d[5].(*string)) = "evidence.txt", "internal"
				*(d[6].(*int64)), *(d[7].(*time.Time)) = 64, databaseTime(created.Add(15*time.Minute))
				*(d[8].(*uuid.UUID)), *(d[9].(*time.Time)), *(d[10].(*time.Time)) = memberID, databaseTime(created), databaseTime(created)
				*(d[11].(*string)), *(d[18].(*int64)) = string(state), 1
				if state == kernel.ScanAvailable {
					verified, size, mime := databaseTime(created.Add(time.Minute)), int64(64), "text/plain"
					*(d[10].(*time.Time)), *(d[12].(*[]byte)), *(d[13].(**int64)) = verified, bytes.Repeat([]byte{1}, 32), &size
					*(d[14].(**string)), *(d[15].(**time.Time)) = &mime, &verified
				}
				return nil
			}}
			object, err := loadDFIRStorageObject(context.Background(), tx, tenantID, storageID)
			if err != nil {
				t.Fatal(err)
			}
			for _, instant := range []time.Time{object.CreatedAt(), object.UpdatedAt(), object.UploadExpiresAt()} {
				if instant.Location() != time.UTC {
					t.Fatal("storage instant is not canonical UTC")
				}
			}
			if !object.CreatedAt().Equal(created) || !object.UploadExpiresAt().Equal(created.Add(15*time.Minute)) {
				t.Fatal("storage instants changed")
			}
			if state == kernel.ScanAvailable && (object.VerifiedAt() == nil || object.VerifiedAt().Location() != time.UTC || !object.CanIssueDownload()) {
				t.Fatal("verified storage lost its download capability")
			}
		})
	}
}
