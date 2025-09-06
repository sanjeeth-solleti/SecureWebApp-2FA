# 🚀 SecureBank Setup Guide

## Quick Start (2 minutes)

### Option 1: Direct Browser Access
1. **Download** the project files
2. **Open** `index.html` in any modern browser
3. **Click** "Show Demo Accounts" button
4. **Login** with provided credentials
5. **Test** 2FA using console-displayed OTP codes

### Option 2: Local Web Server
```bash
# Using Python (recommended for security testing)
python -m http.server 8000
# OR
python3 -m http.server 8000

# Then open: http://localhost:8000
```

## 📋 System Requirements

### Minimum Requirements
- **Browser:** Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **JavaScript:** Enabled (required for security features)
- **Screen Resolution:** 1024x768 minimum
- **Internet:** Not required (fully offline capable)

### Recommended Setup
- **Browser:** Latest Chrome/Firefox with Developer Tools
- **Screen:** 1920x1080 for optimal experience
- **Extensions:** OWASP ZAP, React Developer Tools
- **Environment:** Local web server for HTTPS testing

## 🛠️ Development Environment Setup

### 1. Clone/Download Project
```bash
# If using Git
git clone https://github.com/yourusername/securebank-2fa.git
cd securebank-2fa

# If downloading ZIP
# Extract to: SecureBank-2FA-Project/
```

### 2. Project Structure Verification
```
SecureBank-2FA-Project/
├── index.html ✓             # Main application file
├── README.md ✓               # Project documentation
├── demo-accounts.txt ✓       # Login credentials
├── setup-guide.md ✓          # This setup guide
└── docs/ ✓                   # Documentation folder
    ├── security-features.md ✓
    ├── api-documentation.md ✓
    └── deployment-guide.md ✓
```

### 3. Browser Configuration

#### Chrome Setup (Recommended)
1. **Enable Developer Mode:**
   - Press `F12` or `Ctrl+Shift+I`
   - Go to Settings → Experiments
   - Enable "Security" tab

2. **Security Testing Extensions:**
```bash
# Install Chrome Extensions:
- OWASP ZAP HUD
- EditThisCookie
- Wappalyzer
- React Developer Tools
```

#### Firefox Setup
1. **Security Settings:**
   - Type `about:config` in address bar
   - Set `security.tls.version.min` to `3` (TLS 1.2+)
   - Enable `dom.security.https_first`

### 4. Local HTTPS Setup (Optional)
```bash
# Generate self-signed certificate
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem

# Start HTTPS server
python -m http.server 8000 --bind localhost --directory . --cgi
# Access: https://localhost:8000
```

## 🔐 Security Testing Setup

### 1. Demo Account Configuration
The application includes pre-configured demo accounts:

```javascript
// Located in index.html around line 200
const DEMO_ACCOUNTS = {
    'admin@securebank.com': {
        password: 'admin123',
        role: 'admin',
        phone: '+91-****-***-123'
    },
    'user@securebank.com': {
        password: 'user123', 
        role: 'user',
        phone: '+91-****-***-456'
    }
};
```

### 2. Security Configuration
```javascript
// Security settings (line ~150)
const SECURITY_CONFIG = {
    maxLoginAttempts: 3,        // Brute force protection
    sessionTimeout: 1800000,    // 30 minutes
    otpExpiry: 300000,         // 5 minutes
    csrfToken: generateCSRFToken()
};
```

### 3. Testing Mode Setup
For faster testing, modify timeout values:
```javascript
// Temporary changes for testing
sessionTimeout: 60000,    // 1 minute (instead of 30)
otpExpiry: 120000,       // 2 minutes (instead of 5)
maxLoginAttempts: 2,     // 2 attempts (instead of 3)
```

## 🧪 Feature Testing Guide

### Basic Functionality Test
1. **Login Flow:**
   - Open application
   - Click "Show Demo Accounts"
   - Use admin credentials
   - Complete 2FA verification
   - Access dashboard

2. **Security Features:**
   - Test invalid login (rate limiting)
   - Test XSS in form fields
   - Test SQL injection patterns
   - Verify session timeout

### Advanced Testing
1. **Browser Console Testing:**
```javascript
// Open Console (F12) and test:

// 1. Check security config
console.log(SECURITY_CONFIG);

// 2. Monitor OTP generation
// (OTP codes appear in console during login)

// 3. Test input sanitization
sanitizeInput('<script>alert("test")</script>');

// 4. Check session management
console.log(currentUser);
```

2. **Network Analysis:**
   - Open Network tab in DevTools
   - Monitor for security headers
   - Check for sensitive data exposure
   - Verify HTTPS usage

## 🎯 Interview Demo Preparation

### 1. Demo Script (5 minutes)
```
"Let me demonstrate the SecureBank security features..."

1. LOGIN SECURITY (1 min):
   - "Multi-factor authentication with OTP"
   - "Rate limiting prevents brute force"
   - "Input validation blocks malicious data"

2. DASHBOARD ACCESS (1 min):
   - "Role-based access control"
   - "Session management with timeout"
   - "Secure user context handling"

3. SECURITY FEATURES (2 min):
   - "XSS prevention through sanitization"
   - "SQL injection protection"
   - "CSRF token validation"

4. CODE WALKTHROUGH (1 min):
   - Show key security functions
   - Explain architecture decisions
   - Highlight best practices
```

### 2. Technical Questions Preparation

**Q: How does your 2FA implementation work?**
```
A: "I implemented a 6-digit OTP system with:
- Time-based expiry (5 minutes)  
- Attempt limiting (3 tries max)
- Session-based validation
- Phone/SMS simulation for demo"
```

**Q: How do you prevent XSS attacks?**
```
A: "Multiple layers of XSS protection:
- Input sanitization using textContent
- Output encoding for safe display  
- Content Security Policy headers
- Script source validation"
```

**Q: Explain your session management approach.**
```
A: "Secure session handling with:
- Automatic timeout (30 minutes)
- Activity-based renewal
- Complete cleanup on logout
- CSRF token protection"
```

### 3. Code Highlights to Show

**Security Function Examples:**
```javascript
// 1. Input Sanitization
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// 2. OTP Generation
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// 3. Session Timer
function startSessionTimer() {
    sessionTimer = setTimeout(() => {
        alert('Session expired due to inactivity. Please login again.');
        logout();
    }, SECURITY_CONFIG.sessionTimeout);
}
```

## 🔧 Troubleshooting

### Common Issues

#### Issue 1: Application Won't Load
**Symptoms:** Blank page, console errors  
**Solutions:**
```bash
# Check file path
# Ensure all files in same directory
# Try different browser
# Check JavaScript is enabled
```

#### Issue 2: 2FA Not Working
**Symptoms:** OTP not accepted  
**Solutions:**
```javascript
// Check browser console for OTP code
// Verify console.log is working
// Try refreshing and re-login
// Check developer tools Console tab
```

#### Issue 3: Security Tests Failing
**Symptoms:** XSS/SQL tests don't trigger alerts  
**Solutions:**
```javascript
// Verify input validation is active
// Check console for error messages  
// Try different attack payloads
// Ensure form submission is prevented
```

### Debug Mode Setup
```javascript
// Add to top of script section for debugging
const DEBUG_MODE = true;

if (DEBUG_MODE) {
    // Enhanced logging
    console.log('Debug mode enabled');
    
    // Show all security events
    window.addEventListener('securityEvent', console.log);
    
    // Shorter timeouts for testing
    SECURITY_CONFIG.sessionTimeout = 30000; // 30 seconds
    SECURITY_CONFIG.otpExpiry = 60000;      // 1 minute
}
```

## 📱 Mobile Testing Setup

### Responsive Design Testing
1. **Browser DevTools:**
   - Press F12 → Toggle Device Toolbar
   - Test various screen sizes
   - Verify touch interactions

2. **Real Device Testing:**
   - Connect phone to same network
   - Access via local IP: `http://192.168.1.x:8000`
   - Test mobile browser compatibility

## 🎨 Customization Options

### 1. Branding Changes
```css
/* Modify colors in CSS section */
:root {
    --primary-color: #3498db;    /* Blue theme */
    --secondary-color: #2c3e50;  /* Dark theme */  
    --accent-color: #27ae60;     /* Green accents */
}
```

### 2. Security Settings
```javascript
// Adjust security parameters
const SECURITY_CONFIG = {
    maxLoginAttempts: 5,         // Increase attempts
    sessionTimeout: 3600000,     // 1 hour timeout
    otpExpiry: 600000,          // 10 minute OTP
    passwordMinLength: 8,        // Stronger passwords
};
```

### 3. Feature Toggles
```javascript
// Enable/disable features
const FEATURE_FLAGS = {
    showDemoAccounts: true,      // Hide in production
    consoleLogging: true,        // Disable for security
    autoTimeout: true,           // Session management
    strictValidation: true,      // Enhanced security
};
```

## ✅ Pre-Interview Checklist

### Technical Verification
- [ ] Application loads without errors
- [ ] All demo accounts work correctly
- [ ] 2FA process completes successfully  
- [ ] Security features trigger appropriately
- [ ] Console shows OTP codes clearly
- [ ] Dashboard displays user roles correctly

### Demo Preparation
- [ ] Practiced 5-minute demo script
- [ ] Prepared answers for common questions
- [ ] Code sections bookmarked for quick access
- [ ] Screenshots/videos ready if needed
- [ ] Backup devices/browsers tested

### Documentation Review
- [ ] README.md content familiar
- [ ] Security features document reviewed
- [ ] API documentation understood
- [ ] Test cases execution practiced

## 🎯 Success Metrics

**Technical Depth:** ⭐⭐⭐⭐⭐
- Advanced security implementations
- Enterprise-grade code quality
- Comprehensive documentation

**Practical Skills:** ⭐⭐⭐⭐⭐  
- Working prototype demonstration
- Real-world security scenarios
- Industry best practices applied

**Communication:** ⭐⭐⭐⭐⭐
- Clear technical explanations
- Business impact understanding
- Problem-solving approach

---

**Ready to impress TCS with your secure development expertise!** 🚀

*This setup guide ensures you're fully prepared to demonstrate advanced web security knowledge and practical development skills.*