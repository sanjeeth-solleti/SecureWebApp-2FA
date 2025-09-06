# 🚀 Production Deployment Guide

## Overview
This guide outlines the steps to deploy SecureBank from a demo application to a production-ready banking portal with enterprise-level security and scalability.

## 🎯 Production Architecture

### Target Infrastructure
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │────│   Web Servers    │────│    Database     │
│   (AWS ALB)     │    │   (Auto Scaling) │    │   (RDS MySQL)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────│   API Gateway   │──────────────┘
                        │   (Lambda/ECS)  │
                        └─────────────────┘
                                │
                    ┌─────────────────┐
                    │   External      │
                    │   Services      │
                    │ • SMS Gateway   │
                    │ • Email Service │
                    │ • Monitoring    │
                    └─────────────────┘
```

## 🏗️ Infrastructure Setup

### 1. Cloud Platform (AWS Recommended)

#### EC2 Configuration
```yaml
# Production Environment
Instance Type: t3.medium (minimum)
CPU: 2 vCPUs
RAM: 4 GB
Storage: 50 GB SSD
OS: Ubuntu 22.04 LTS
Security Groups: Custom (ports 80, 443 only)
```

#### RDS Database Setup
```yaml
Engine: MySQL 8.0
Instance: db.t3.micro (start), scale to db.t3.medium
Storage: 100 GB GP2 SSD
Multi-AZ: Yes (for production)
Backup: 7-day retention
Encryption: Enabled (AES-256)
```

#### S3 Configuration
```yaml
Buckets:
  - securebank-static-assets
  - securebank-logs
  - securebank-backups
Encryption: SSE-S3 enabled
Versioning: Enabled
Public Access: Blocked
```

### 2. Domain & SSL Setup

#### Domain Configuration
```bash
# Purchase domain through AWS Route 53
Domain: securebank.yourdomain.com
DNS Records:
  - A Record: → Load Balancer IP
  - CNAME: www → securebank.yourdomain.com
  - MX Record: → Email service
```

#### SSL Certificate (Let's Encrypt)
```bash
# Install Certbot
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Generate certificate
sudo certbot --nginx -d securebank.yourdomain.com -d www.securebank.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 🔧 Backend Implementation

### 1. Node.js API Server

#### Project Structure
```
securebank-api/
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── userController.js
│   │   └── accountController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── validation.js
│   │   └── security.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Account.js
│   │   └── Transaction.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── users.js
│   │   └── accounts.js
│   ├── services/
│   │   ├── otpService.js
│   │   ├── emailService.js
│   │   └── smsService.js
│   └── utils/
│       ├── encryption.js
│       ├── validation.js
│       └── logger.js
├── tests/
├── config/
└── package.json
```

#### Core Dependencies
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "helmet": "^6.1.5",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^6.15.0",
    "mysql2": "^3.3.0",
    "sequelize": "^6.31.1",
    "nodemailer": "^6.9.1",
    "speakeasy": "^2.0.0",
    "winston": "^3.8.2",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3"
  }
}
```

### 2. Database Schema

#### User Management
```sql
-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    phone VARCHAR(20),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_role (role)
);

-- Sessions table  
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_expires (expires_at)
);

-- Audit logs
CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created_at (created_at)
);
```

### 3. Security Middleware

#### Authentication Middleware
```javascript
// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const { User } = require('../models');

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

module.exports = { authenticateToken };
```

#### Rate Limiting
```javascript
// src/middleware/security.js
const rateLimit = require('express-rate-limit');

// Login rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many login attempts, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// API rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many API requests, please slow down.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = { loginLimiter, apiLimiter };
```

#### Input Validation
```javascript
// src/middleware/validation.js
const { body, validationResult } = require('express-validator');

const loginValidation = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .isLength({ max: 254 })
        .withMessage('Valid email required'),
    body('password')
        .isLength({ min: 6, max: 128 })
        .withMessage('Password must be 6-128 characters'),
    body('userType')
        .isIn(['admin', 'user'])
        .withMessage('Invalid user type'),
];

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors.array()
        });
    }
    next();
};

module.exports = { loginValidation, handleValidationErrors };
```

## 🔒 Security Implementation

### 1. Environment Configuration

#### Production Environment Variables
```bash
# .env.production
NODE_ENV=production
PORT=3000

# Database
DB_HOST=securebank-db.xxxxx.rds.amazonaws.com
DB_PORT=3306
DB_NAME=securebank_prod
DB_USER=securebank_app
DB_PASSWORD=super_secure_password_here

# JWT Configuration
JWT_SECRET=your_super_long_jwt_secret_key_here_64_chars_minimum
JWT_EXPIRES_IN=30m
JWT_REFRESH_SECRET=your_refresh_token_secret_here
JWT_REFRESH_EXPIRES_IN=7d

# Encryption
ENCRYPTION_KEY=your_32_byte_encryption_key_here
HASH_ROUNDS=12

# External Services
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your_smtp_username
SMTP_PASS=your_smtp_password

SMS_API_KEY=your_sms_provider_api_key
SMS_API_SECRET=your_sms_provider_secret

# Security
ALLOWED_ORIGINS=https://securebank.yourdomain.com
CORS_CREDENTIALS=true
HELMET_CSP_DIRECTIVES=default-src 'self'; script-src 'self' cdnjs.cloudflare.com

# Monitoring
LOG_LEVEL=info
SENTRY_DSN=your_sentry_dsn_here
```

### 2. Server Configuration

#### Express.js Security Setup
```javascript
// src/app.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "cdnjs.cloudflare.com"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS.split(','),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global rate limiting
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: 'Too many requests from this IP'
}));
```

### 3. Database Security

#### Connection Configuration
```javascript
// src/config/database.js
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    dialect: 'mysql',
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: true
        },
        encrypt: true
    },
    pool: {
        max: 10,
        min: 0,
        acquire: 30000,
        idle: 10000
    },
    logging: process.env.NODE_ENV === 'development' ? console.log : false
});

module.exports = sequelize;
```

## 🔄 CI/CD Pipeline

### 1. GitHub Actions Workflow

#### .github/workflows/deploy.yml
```yaml
name: Deploy to Production

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run security audit
        run: npm audit --audit-level high
      
      - name: Run tests
        run: npm test
      
      - name: Run security tests
        run: npm run test:security
      
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Deploy to ECS
        run: |
          aws ecs update-service --cluster securebank-cluster --service securebank-service --force-new-deployment
```

### 2. Docker Configuration

#### Dockerfile
```dockerfile
FROM node:18-alpine

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S securebank -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=securebank:nodejs . .

# Security: Remove unnecessary files
RUN rm -rf tests/ docs/ .git/

# Set user
USER securebank

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

#### docker-compose.prod.yml
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    depends_on:
      - redis
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped

volumes:
  redis_data:
```

## 🌐 Frontend Deployment

### 1. Build Process

#### Production Build Script
```bash
#!/bin/bash
# build-production.sh

echo "🔨 Building SecureBank for Production..."

# Create production directory
mkdir -p dist/

# Copy main files
cp index.html dist/
cp -r assets/ dist/ 2>/dev/null || true

# Minify HTML
npx html-minifier --collapse-whitespace --remove-comments \
    --minify-css --minify-js dist/index.html -o dist/index.html

# Add production security headers
cat >> dist/.htaccess << EOF
# Security Headers
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' cdnjs.cloudflare.com"

# Force HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
EOF

echo "✅ Production build complete!"
```

### 2. CDN Configuration (AWS CloudFront)

#### Distribution Settings
```json
{
  "Origins": [
    {
      "DomainName": "securebank-origin.s3.amazonaws.com",
      "Id": "S3-securebank-origin",
      "S3OriginConfig": {
        "OriginAccessIdentity": "origin-access-identity/cloudfront/EXAMPLE"
      }
    }
  ],
  "DefaultCacheBehavior": {
    "TargetOriginId": "S3-securebank-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
    "Compress": true
  },
  "CustomErrorResponses": [
    {
      "ErrorCode": 404,
      "ResponsePagePath": "/index.html",
      "ResponseCode": 200,
      "ErrorCachingMinTTL": 300
    }
  ],
  "ViewerCertificate": {
    "AcmCertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/example",
    "SslSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021"
  }
}
```

## 📊 Monitoring & Logging

### 1. Application Monitoring

#### Winston Logger Configuration
```javascript
// src/utils/logger.js
const winston = require('winston');

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'securebank-api' },
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log' 
        }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ],
});

// Security event logging
logger.security = (event, details) => {
    logger.warn('SECURITY_EVENT', {
        event,
        details,
        timestamp: new Date().toISOString()
    });
};

module.exports = logger;
```

### 2. Health Checks

#### Health Check Endpoint
```javascript
// src/routes/health.js
const express = require('express');
const router = express.Router();
const sequelize = require('../config/database');

router.get('/health', async (req, res) => {
    const health = {
        status: 'UP',
        timestamp: new Date().toISOString(),
        checks: {
            database: 'DOWN',
            memory: 'UP',
            disk: 'UP'
        }
    };
    
    try {
        // Database connectivity check
        await sequelize.authenticate();
        health.checks.database = 'UP';
        
        // Memory usage check
        const memUsage = process.memoryUsage();
        health.memory = {
            used: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
            total: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB'
        };
        
        res.status(200).json(health);
    } catch (error) {
        health.status = 'DOWN';
        health.error = error.message;
        res.status(503).json(health);
    }
});

module.exports = router;
```

### 3. Performance Monitoring

#### New Relic Configuration
```javascript
// newrelic.js
'use strict'

exports.config = {
    app_name: ['SecureBank Production'],
    license_key: process.env.NEW_RELIC_LICENSE_KEY,
    logging: {
        level: 'info'
    },
    allow_all_headers: true,
    attributes: {
        exclude: [
            'request.headers.cookie',
            'request.headers.authorization',
            'response.headers.set-cookie*'
        ]
    },
    security: {
        enabled: true,
        mode: 'IAST'
    }
}
```

## 🚀 Deployment Checklist

### Pre-Deployment
- [ ] Security audit completed
- [ ] All tests passing (unit, integration, security)
- [ ] Database migrations tested
- [ ] SSL certificates configured
- [ ] Environment variables secured
- [ ] Backup strategy implemented
- [ ] Monitoring setup verified
- [ ] Load testing completed
- [ ] Disaster recovery plan ready

### Deployment Steps
1. **Database Migration:**
```bash
npm run migrate:prod
```

2. **Application Deployment:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

3. **Verification:**
```bash
# Health check
curl https://securebank.yourdomain.com/health

# Security headers check
curl -I https://securebank.yourdomain.com

# Load balancer check
curl https://securebank.yourdomain.com/api/status
```

### Post-Deployment
- [ ] Application health verified
- [ ] Security scans completed
- [ ] Performance benchmarks met
- [ ] Monitoring alerts configured
- [ ] Backup verification successful
- [ ] Documentation updated
- [ ] Team notification sent

## 🔐 Security Hardening

### 1. Server Security

#### Ubuntu Security Configuration
```bash
# System updates
sudo apt update && sudo apt upgrade -y

# Firewall configuration
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Fail2ban installation
sudo apt install fail2ban -y
sudo systemctl enable fail2ban

# Automatic security updates
sudo apt install unattended-upgrades -y
echo 'Unattended-Upgrade::Automatic-Reboot "false";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
```

### 2. Application Security

#### Security Scanner Integration
```bash
# OWASP Dependency Check
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file securebank-sbom.json

# Security audit
npm audit --audit-level high

# Vulnerability scanning with Snyk
npx snyk test
npx snyk monitor
```

## 📈 Scaling Strategy

### 1. Horizontal Scaling

#### Auto Scaling Configuration
```yaml
# AWS Auto Scaling Group
AutoScalingGroup:
  MinSize: 2
  MaxSize: 10
  DesiredCapacity: 2
  TargetGroupARNs:
    - !Ref ApplicationLoadBalancerTargetGroup
  LaunchTemplate:
    LaunchTemplateId: !Ref LaunchTemplate
    Version: !GetAtt LaunchTemplate.LatestVersionNumber
    
ScaleUpPolicy:
  Type: AWS::AutoScaling::ScalingPolicy
  PolicyType: TargetTrackingScaling
  TargetTrackingConfiguration:
    PredefinedMetricSpecification:
      PredefinedMetricType: ASGAverageCPUUtilization
    TargetValue: 70
```

### 2. Database Scaling

#### Read Replicas Setup
```sql
-- Master-slave replication
CREATE USER 'replication'@'%' IDENTIFIED BY 'secure_replication_password';
GRANT REPLICATION SLAVE ON *.* TO 'replication'@'%';

-- Read-only queries routing
-- Configure application to use read replicas for SELECT queries
-- Keep write operations on master database
```

## 📋 Maintenance Procedures

### 1. Regular Maintenance Tasks

#### Weekly Tasks
```bash
#!/bin/bash
# weekly-maintenance.sh

echo "🔧 Weekly maintenance started..."

# Security updates
sudo apt update && sudo apt upgrade -y

# Log rotation
sudo logrotate -f /etc/logrotate.conf

# Database optimization
mysql -u admin -p -e "OPTIMIZE TABLE users, sessions, audit_logs;"

# Certificate renewal check
sudo certbot renew --dry-run

echo "✅ Weekly maintenance completed!"
```

### 2. Backup Strategy

#### Automated Backup Script
```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/backups/mysql"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="securebank_prod"

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
mysqldump -u backup_user -p$MYSQL_BACKUP_PASSWORD \
    --single-transaction --routines --triggers \
    $DB_NAME > $BACKUP_DIR/securebank_${TIMESTAMP}.sql

# Encrypt backup
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
    $BACKUP_DIR/securebank_${TIMESTAMP}.sql

# Upload to S3
aws s3 cp $BACKUP_DIR/securebank_${TIMESTAMP}.sql.gpg \
    s3://securebank-backups/database/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "securebank_*.sql*" -mtime +30 -delete

echo "✅ Database backup completed: $TIMESTAMP"
```

## 🎯 Success Metrics

### Key Performance Indicators
- **Uptime:** 99.9% availability target
- **Response Time:** < 200ms average API response
- **Security:** Zero critical vulnerabilities
- **Scalability:** Handle 1000+ concurrent users
- **Compliance:** SOC 2, PCI DSS ready

### Monitoring Dashboards
- **Application Performance:** New Relic/DataDog
- **Infrastructure:** CloudWatch/Grafana  
- **Security:** AWS Security Hub/Splunk
- **Business Metrics:** Custom analytics dashboard

---

**🚀 Your SecureBank application is now ready for enterprise production deployment!**

*This comprehensive deployment guide ensures your application meets enterprise security standards and can scale to handle real banking workloads.*