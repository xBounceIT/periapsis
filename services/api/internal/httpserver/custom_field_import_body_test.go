package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomFieldImportBodyPreservesMissingNullAndEmpty(t *testing.T) {
	request := httptest.NewRequest(
		"POST", "/api/v1/tenants/ignored/custom-field-imports",
		strings.NewReader(`{"objectType":"alert","mode":"commit","rows":[{"targetId":"0198c97d-cf4f-7000-8000-000000000101","expectedVersion":7,"fields":[{"key":"missing"},{"key":"nullable","value":null},{"key":"empty","value":""}]}]}`),
	)
	request.Header.Set("Content-Type", "application/json")
	var body customFieldImportRequestBody
	if err := decodeCustomFieldImportRequestBody(request, &body); err != nil {
		t.Fatal(err)
	}
	fields := body.Rows[0].Fields
	if fields[0].Present || len(fields[0].Value) != 0 ||
		!fields[1].Present || string(fields[1].Value) != "null" ||
		!fields[2].Present || string(fields[2].Value) != `""` {
		t.Fatalf("presence projection = %#v", fields)
	}
}

func TestCustomFieldImportBodyRejectsDuplicateAndOversizedCells(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate": `{"objectType":"alert","objectType":"case","mode":"commit","rows":[]}`,
		"oversized": `{"objectType":"alert","mode":"commit","rows":[{"targetId":"0198c97d-cf4f-7000-8000-000000000101","expectedVersion":1,"fields":[{"key":"value","value":"` + strings.Repeat("x", customFieldImportMaximumCellBytes) + `"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := decodeCustomFieldImportRequestBody(request, &customFieldImportRequestBody{}); err == nil {
				t.Fatal("hostile body was accepted")
			}
		})
	}
}
