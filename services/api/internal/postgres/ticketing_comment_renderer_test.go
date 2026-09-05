package postgres

import (
	"context"
	"errors"
	"testing"

	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestCreateCommentPropagatesRendererValidationBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()

	repository := &TicketingRepository{}
	result, err := repository.CreateComment(context.Background(), application.CommentWrite{})
	if !errors.Is(err, application.ErrInvalidInput) || result.Comment.Revision != 0 || result.Replayed {
		t.Fatalf("CreateComment() = %#v, %v; want zero ErrInvalidInput", result, err)
	}
}
