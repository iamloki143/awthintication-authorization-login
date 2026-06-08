# ASP.NET Core JWT Authentication API

A secure Authentication and Authorization REST API built using ASP.NET Core Web API, Entity Framework Core, PostgreSQL, JWT Authentication, Refresh Tokens, Email Verification, and Password Reset functionality.

---

## Features

### Authentication
- User Registration
- User Login
- JWT Access Token Generation
- Refresh Token Authentication
- Secure Logout

### Authorization
- Role-Based Authorization
- Protected Endpoints
- Admin-Only Endpoints

### Account Security
- BCrypt Password Hashing
- Email Verification
- Forgot Password
- Password Reset
- Refresh Token Revocation

### Database
- PostgreSQL
- Entity Framework Core
- Code-First Migrations

### API Documentation
- Swagger UI Integration

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| ASP.NET Core Web API | Backend Framework |
| Entity Framework Core | ORM |
| PostgreSQL | Database |
| JWT | Authentication |
| BCrypt.Net | Password Hashing |
| Swagger | API Testing & Documentation |

---

## Database Tables

### Users
Stores user account information.

### RefreshTokens
Stores refresh tokens for JWT renewal.

### EmailVerificationTokens
Stores email verification tokens.

### PasswordResetTokens
Stores password reset tokens.

---

## API Endpoints

### Authentication

#### Register User

```http
POST /api/auth/register
```

#### Login User

```http
POST /api/auth/login
```

#### Refresh Access Token

```http
POST /api/auth/refresh
```

#### Logout

```http
POST /api/auth/logout
```

---

### Email Verification

#### Verify Email

```http
GET /api/auth/verify-email
```

---

### Password Recovery

#### Forgot Password

```http
POST /api/auth/forgot-password
```

#### Reset Password

```http
POST /api/auth/reset-password
```

---

### Protected Routes

#### User Profile

```http
GET /api/auth/profile
```

Requires a valid JWT Access Token.

#### Admin Access

```http
GET /api/auth/admin
```

Requires:
- Valid JWT Token
- Admin Role

---

## Authentication Flow

### Registration

1. User registers.
2. Password is hashed using BCrypt.
3. User is saved in PostgreSQL.
4. Email verification token is generated.

### Login

1. User enters username and password.
2. Password is verified.
3. JWT Access Token is generated.
4. Refresh Token is generated.

### Token Refresh

1. Client sends Refresh Token.
2. Server validates token.
3. New JWT Access Token is generated.

### Logout

1. Refresh Token is revoked.
2. User must login again.

### Forgot Password

1. User submits email.
2. Password reset token is generated.
3. User resets password using token.

---

## Project Structure

```text
LoginApi
│
├── Controllers
│   └── AuthController.cs
│
├── Data
│   └── AppDbContext.cs
│
├── DTOs
│   ├── RegisterDto.cs
│   ├── LoginDto.cs
│   ├── RefreshRequestDto.cs
│   ├── ForgotPasswordDto.cs
│   └── ResetPasswordDto.cs
│
├── Models
│   ├── User.cs
│   ├── RefreshToken.cs
│   ├── EmailVerificationToken.cs
│   └── PasswordResetToken.cs
│
├── Program.cs
├── appsettings.json
└── README.md
```

---

## Running the Project

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/aspnet-jwt-authentication-api.git
cd aspnet-jwt-authentication-api
```

### Restore Packages

```bash
dotnet restore
```

### Apply Migrations

```bash
dotnet ef database update
```

### Run Application

```bash
dotnet run
```

### Open Swagger

```text
https://localhost:xxxx/swagger
```

---

## Security Features

- JWT Authentication
- Refresh Tokens
- BCrypt Password Hashing
- Role-Based Authorization
- Email Verification
- Password Reset Tokens
- Refresh Token Revocation

---

## Future Improvements

- SMTP Email Integration
- Refresh Token Rotation
- Google Login
- GitHub Login
- Two-Factor Authentication (2FA)
- Rate Limiting
- Account Lockout Protection

---

## Learning Outcomes

This project demonstrates:

- ASP.NET Core Web API Development
- Authentication & Authorization
- JWT Security
- Refresh Token Implementation
- Entity Framework Core
- PostgreSQL Integration
- Secure Password Storage
- REST API Design
- Swagger Documentation

---

## Author

Lokesh Kumar
