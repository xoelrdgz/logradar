package ports

// ProcessingObserver defines the interface for observing processing results.
// Used to track metrics for all processed lines, not just alerts.
type ProcessingObserver interface {
	// IncrementLinesProcessedByResult records the result of processing a line.
	//
	// Parameters:
	//   - result: The classification of the line (e.g., "clean", "malicious", "error")
	//
	// Thread Safety: Implementations MUST be safe for concurrent calls.
	IncrementLinesProcessedByResult(result string)
}
