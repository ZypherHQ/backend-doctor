package api

type CreateUserRequest struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type RegisterUserRequest struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}
