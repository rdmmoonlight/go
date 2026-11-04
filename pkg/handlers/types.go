package handlers

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Client   string `json:"client"`
}

type UpdateProfileRequest struct {
	Name        *string `json:"name,omitempty"`
	UserName    *string `json:"userName,omitempty"`
	PhoneNumber *string `json:"phoneNumber,omitempty"`
	Bio         *string `json:"bio,omitempty"`
	AvatarURL   *string `json:"avatarUrl,omitempty"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type DeleteAccountRequest struct {
	Password string `json:"password"`
}

type AuthResponse struct {
	Message string      `json:"message"`
	Token   string      `json:"token,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}
