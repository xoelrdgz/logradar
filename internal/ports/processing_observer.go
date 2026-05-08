package ports

type ProcessingObserver interface {
	IncrementLinesProcessedByResult(result string)
}

type DetailedProcessingObserver interface {
	ProcessingObserver
	IncrementProcessingErrors(errorType string)
	IncrementQueueOverflow()
	IncrementParseErrors()
	IncrementParseErrorByReason(reason string)
	IncrementAlerterErrors(output string)
}
