package utils

import (
	"encoding/json"
	"net/http"
)

type ErrorDetails struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Property string `json:"property,omitempty"`
}

type ErrorResponse struct {
	Status  int            `json:"status"`
	Message string         `json:"message"`
	Details []ErrorDetails `json:"details,omitempty"`
}

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func WriteJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := Response{
		Status:  status,
		Message: http.StatusText(status),
		Data:    data,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func WriteErrorResponse(w http.ResponseWriter, status int, message string, details ...ErrorDetails) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	errorResponse := ErrorResponse{
		Status:  status,
		Message: message,
		Details: details,
	}

	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}
