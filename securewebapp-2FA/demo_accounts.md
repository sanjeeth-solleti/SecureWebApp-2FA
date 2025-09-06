# 🔐 SecureBank Demo Accounts

## Administrator Account
**Email:** admin@securebank.com  
**Password:** admin123  
**Account Type:** Administrator  
**Phone:** +91-****-***-123  
**Privileges:** Full system access, user management, security settings

## Standard User Account  
**Email:** user@securebank.com  
**Password:** user123  
**Account Type:** Standard User  
**Phone:** +91-****-***-456  
**Privileges:** Account access, transaction history, profile management

## 2FA Demo Information
- **OTP Codes** are displayed in the browser console for demo purposes
- **Default OTP Expiry:** 5 minutes
- **Maximum Attempts:** 3 per OTP generation
- **Resend Functionality:** Available after failed attempts

## Security Notes
⚠️ **Important:** These are demo credentials for testing purposes only.  
⚠️ In production, passwords would be hashed using bcrypt or similar  
⚠️ 2FA would integrate with real SMS/Email services  
⚠️ All sensitive data would be stored securely in databases

## Testing Scenarios

### Successful Login Flow
1. Enter valid credentials above
2. Select correct account type
3. Note the OTP displayed in console  
4. Enter OTP in 2FA form
5. Access dashboard successfully

### Security Testing
1. **Invalid Credentials:** Try wrong password (rate limiting kicks in)
2. **XSS Testing:** Try `<script>alert('xss')</script>` in email field
3. **SQL Injection:** Try `'; DROP TABLE users;--` in password field
4. **Session Timeout:** Wait 30 minutes (or modify timeout for testing)
5. **OTP Expiry:** Wait 5 minutes before entering OTP
6. **Brute Force:** Try multiple wrong OTPs (gets locked after 3 attempts)

### Role-Based Testing
- Login as **admin** to see administrator dashboard features
- Login as **user** to see standard user interface
- Notice different privilege levels and available actions