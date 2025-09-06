# 📡 API Documentation - SecureBank

## Overview
This document outlines the API specifications for the SecureBank application. While the current implementation is client-side, this documentation describes the production-ready backend API structure.

## 🔧 Base Configuration

**Base URL:** `https://api.securebank.com/v1`  
**Content-Type:** `application/json`  
**Authentication:** Bearer Token + 2FA Verification  
**Rate Limiting:** 100 requests/minute per user  

## 🔐 Authentication Endpoints

### POST /auth/login
**Description:** Initial user authentication  
**Rate Limit:** 5 attempts/minute per IP

**Request Body:**
```json
{
    "email": "user@securebank.com",
    "password": "securePassword",
    "userType": "admin|user",
    "csrfToken": "csrf-token-here"
}
```

**Response (Success):**
```json
{
    "status": "2fa_required",
    "message": "OTP sent to registered device",
    "sessionId": "temp-session-id",
    "otpExpiry": "2024-01-15T10:35:00Z",
    "maskedPhone": "+91-****-***-123"
}
```

**Response (Failure):**
```json
{
    "status": "error",
    "message": "Invalid credentials",
    "attemptsRemaining": 2,
    "lockoutTime": null
}
```

### POST /auth/verify-otp
**Description:** Two-factor authentication verification  
**Rate Limit:** 3 attempts per session

**Request Body:**
```json
{
    "sessionId": "temp-session-id",
    "otp": "123456",
    "csrfToken": "csrf-token-here"
}
```

**Response (Success):**
```json
{
    "status": "success",
    "message": "Authentication successful",
    "accessToken": "jwt-access-token",
    "refreshToken": "jwt-refresh-token",
    "user": {
        "id": "user-123",
        "email": "user@securebank.com",
        "role": "admin",
        "lastLogin": "2024-01-15T10:30:00Z",
        "permissions": ["read:accounts", "write:transactions"]
    },
    "sessionExpiry": "2024-01-15T11:00:00Z"
}
```

### POST /auth/resend-otp
**Description:** Resend OTP code  
**Rate Limit:** 3 requests per session

**Request Body:**
```json
{
    "sessionId": "temp-session-id",
    "csrfToken": "csrf-token-here"
}
```

### POST /auth/logout
**Description:** Secure user logout  
**Authentication:** Required

**Headers:**
```
Authorization: Bearer <access-token>
X-CSRF-Token: <csrf-token>
```

**Response:**
```json
{
    "status": "success",
    "message": "Logged out successfully"
}
```

### POST /auth/refresh
**Description:** Refresh access token  
**Rate Limit:** 10 requests/hour per user

**Request Body:**
```json
{
    "refreshToken": "jwt-refresh-token",
    "csrfToken": "csrf-token-here"
}
```

## 👤 User Management Endpoints

### GET /users/profile
**Description:** Get current user profile  
**Authentication:** Required  
**Permissions:** read:profile

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "id": "user-123",
        "email": "user@securebank.com",
        "role": "admin",
        "profile": {
            "firstName": "John",
            "lastName": "Doe",
            "phone": "+91-9876543210",
            "lastLogin": "2024-01-15T10:30:00Z",
            "accountStatus": "active",
            "twoFactorEnabled": true
        },
        "preferences": {
            "language": "en",
            "timezone": "Asia/Kolkata",
            "notifications": {
                "email": true,
                "sms": true
            }
        }
    }
}
```

### PUT /users/profile
**Description:** Update user profile  
**Authentication:** Required  
**Permissions:** write:profile

**Request Body:**
```json
{
    "profile": {
        "firstName": "John",
        "lastName": "Doe",
        "phone": "+91-9876543210"
    },
    "preferences": {
        "language": "en",
        "timezone": "Asia/Kolkata",
        "notifications": {
            "email": true,
            "sms": false
        }
    }
}
```

### POST /users/change-password
**Description:** Change user password  
**Authentication:** Required + 2FA

**Request Body:**
```json
{
    "currentPassword": "oldPassword",
    "newPassword": "newSecurePassword",
    "confirmPassword": "newSecurePassword",
    "otp": "123456"
}
```

## 🏦 Account Endpoints

### GET /accounts
**Description:** Get user accounts  
**Authentication:** Required  
**Permissions:** read:accounts

**Response:**
```json
{
    "status": "success",
    "data": {
        "accounts": [
            {
                "id": "acc-123",
                "accountNumber": "****-****-1234",
                "accountType": "savings",
                "balance": 45230.50,
                "currency": "INR",
                "status": "active",
                "lastTransaction": "2024-01-15T09:30:00Z"
            }
        ],
        "totalBalance": 45230.50,
        "accountCount": 1
    }
}
```

### GET /accounts/{accountId}/transactions
**Description:** Get account transactions  
**Authentication:** Required  
**Permissions:** read:transactions

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (max: 100)
- `fromDate`: Start date (ISO format)
- `toDate`: End date (ISO format)
- `type`: Transaction type (credit|debit|all)

**Response:**
```json
{
    "status": "success",
    "data": {
        "transactions": [
            {
                "id": "txn-123",
                "type": "credit",
                "amount": 1000.00,
                "currency": "INR",
                "description": "Salary Credit",
                "date": "2024-01-15T09:30:00Z",
                "balance": 45230.50,
                "reference": "SAL-2024-001"
            }
        ],
        "pagination": {
            "page": 1,
            "limit": 20,
            "total": 100,
            "pages": 5
        }
    }
}
```

## 🛡️ Security Endpoints

### GET /security/audit-log
**Description:** Get security audit log  
**Authentication:** Required  
**Permissions:** admin:read:audit

**Query Parameters:**
- `page`: Page number
- `limit`: Items per page
- `eventType`: Event type filter
- `fromDate`: Start date

**Response:**
```json
{
    "status": "success",
    "data": {
        "auditEvents": [
            {
                "id": "audit-123",
                "userId": "user-123",
                "eventType": "login_success",
                "timestamp": "2024-01-15T10:30:00Z",
                "ipAddress": "192.168.1.100",
                "userAgent": "Mozilla/5.0...",
                "details": {
                    "method": "2fa",
                    "location": "Mumbai, IN"
                }
            }
        ]
    }
}
```

### POST /security/2fa/enable
**Description:** Enable 2FA for user  
**Authentication:** Required + Password verification

**Request Body:**
```json
{
    "password": "userPassword",
    "method": "sms|email|app",
    "phoneNumber": "+91-9876543210"
}
```

### POST /security/report-incident
**Description:** Report security incident  
**Authentication:** Required

**Request Body:**
```json
{
    "incidentType": "suspicious_activity|data_breach|unauthorized_access",
    "description": "Detailed description of incident",
    "severity": "low|medium|high|critical",
    "affectedSystems": ["web_portal", "mobile_app"]
}
```

## 📊 Analytics Endpoints (Admin Only)

### GET /analytics/dashboard
**Description:** Get dashboard analytics  
**Authentication:** Required  
**Permissions:** admin:read:analytics

**Response:**
```json
{
    "status": "success",
    "data": {
        "userMetrics": {
            "totalUsers": 15420,
            "activeUsers": 12340,
            "newRegistrations": 234
        },
        "securityMetrics": {
            "successfulLogins": 45670,
            "failedLogins": 234,
            "blockedAttempts": 12,
            "2faEnabled": 98.5
        },
        "systemMetrics": {
            "uptime": 99.97,
            "responseTime": 125,
            "errorRate": 0.02
        }
    }
}
```

## 🚨 Error Handling

### Standard Error Response
```json
{
    "status": "error",
    "error": {
        "code": "VALIDATION_FAILED",
        "message": "Request validation failed",
        "details": [
            {
                "field": "email",
                "message": "Invalid email format"
            }
        ],
        "requestId": "req-123456"
    }
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error
- `503` - Service Unavailable

### Error Codes
- `INVALID_CREDENTIALS` - Login credentials are incorrect
- `ACCOUNT_LOCKED` - Account temporarily locked
- `OTP_EXPIRED` - OTP has expired
- `OTP_INVALID` - Invalid OTP provided
- `SESSION_EXPIRED` - User session has expired
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `RATE_LIMIT_EXCEEDED` - API rate limit exceeded
- `VALIDATION_FAILED` - Request validation failed
- `2FA_REQUIRED` - Two-factor authentication required
- `MAINTENANCE_MODE` - System under maintenance

## 🔒 Security Headers

All API responses include security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Rate-Limit-Remaining: 95
X-Rate-Limit-Reset: 1610712000
```

## 📋 Request/Response Examples

### Complete Login Flow

**Step 1: Initial Login**
```bash
curl -X POST https://api.securebank.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@securebank.com",
    "password": "userPassword",
    "userType": "user",
    "csrfToken": "csrf-token-here"
  }'
```

**Step 2: OTP Verification**
```bash
curl -X POST https://api.securebank.com/v1/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "temp-session-id",
    "otp": "123456",
    "csrfToken": "csrf-token-here"
  }'
```

**Step 3: Access Protected Resource**
```bash
curl -X GET https://api.securebank.com/v1/users/profile \
  -H "Authorization: Bearer jwt-access-token" \
  -H "X-CSRF-Token: csrf-token"
```

## 🧪 Testing & Development

### Postman Collection
A complete Postman collection is available with pre-configured requests for all endpoints.

### Test Environment
**Base URL:** `https://api-test.securebank.com/v1`  
**Test Accounts:** See `demo-accounts.txt`  
**Rate Limits:** Relaxed for testing

### Mock Server
The application includes a mock server mode for frontend development without backend dependencies.

---

*This API documentation provides a complete specification for production-ready SecureBank backend services.*