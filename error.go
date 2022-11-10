package main

type ServerError struct {
	Message    string
	StatusCode int
}

func NewServerError(statusCode int, message string) *ServerError {
	return &ServerError{StatusCode: statusCode, Message: message}
}

func (e *ServerError) Error() string {
	return e.Message
}
