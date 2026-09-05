package ticketing

// Ticket-export object keys are an immutable inter-process contract shared by
// the API download boundary and the worker that publishes the artifact. None
// of the exported query contents, customer data, or storage credentials may
// contribute to the key.
const ticketExportObjectPrefix = "ticket-exports/v1"

// TicketExportArtifactObjectKeys returns the create-only staging key and the
// immutable final key for one exact tenant/job/artifact tuple.
func TicketExportArtifactObjectKeys(
	tenantID EntityID,
	jobID EntityID,
	artifactID EntityID,
) (temporary string, final string, err error) {
	if !validEntityID(tenantID) || !validEntityID(jobID) || !validEntityID(artifactID) {
		return "", "", ErrInvalidTicketExport
	}
	base := ticketExportObjectPrefix + "/" + tenantID.String() + "/" + jobID.String()
	return base + "/temporary/" + artifactID.String() + ".csv",
		base + "/artifacts/" + artifactID.String() + ".csv", nil
}
