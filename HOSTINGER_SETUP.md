# Hostinger Cloud Environment Setup Guide

## Overview

This backend has been configured to work correctly with **Hostinger Cloud Startup**.

### The Problem
Hostinger Cloud runs Node.js in an isolated container where:
- The `.env` file on disk is **NOT automatically loaded**
- Environment variables must be set via **hPanel → Node.js → Environment Variables**
- If `dotenv` is used unconditionally, it can override or conflict with injected variables

### The Solution
This codebase now:
1. **Only loads `.env` file in non-production** (`NODE_ENV !== "production"`)
2. **In production**, relies exclusively on `process.env` values injected by Hostinger
3. **Fails fast** if critical environment variables are missing
4. **No hardcoded fallbacks** for security-sensitive values

---

## Required Environment Variables

You **MUST** set these in Hostinger hPanel:

### Critical (Server won't start without these)

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `production` |
| `MONGO_URI` | MongoDB connection string | `mongodb+srv://user:pass@cluster.mongodb.net/db` |
| `JWT_SECRET` | Secret for JWT signing (min 32 chars) | `your-super-secret-key-here-at-least-32-chars` |

### Important (Needed for full functionality)

| Variable | Description | Example |
|----------|-------------|---------|
| `CLIENT_URL` | Frontend URL (for CORS & emails) | `https://your-frontend.com` |
| `ADMIN_URL` | Admin panel URL (for CORS) | `https://admin.your-site.com` |
| `CLOUDINARY_URL` | Cloudinary connection string | `cloudinary://123:abc@cloud-name` |
| `PORT` | Server port (usually auto-set by Hostinger) | `3000` |

### Optional (Feature-specific)

| Variable | Description | Example |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username/email | `your-email@gmail.com` |
| `SMTP_PASS` | SMTP password/app password | `your-app-password` |
| `SMTP_SECURE` | Use TLS (true for port 465) | `false` |
| `GEMINI_API_KEY` | Google AI for agreement generation | `your-gemini-api-key` |
| `COOKIE_DOMAIN` | Domain for cookies (cross-subdomain) | `.your-domain.com` |
| `AGREEMENT_SECRET_KEY` | Separate key for agreement signing | `another-secret-key` |
| `OTP_SECRET` | Separate key for OTP hashing | Falls back to JWT_SECRET |

---

## How to Set Environment Variables in Hostinger

1. Log in to [hPanel](https://hpanel.hostinger.com)
2. Go to **Websites** → Select your website
3. Click **Manage**
4. In the left sidebar, find **Node.js** or **Advanced** section
5. Click **Environment Variables**
6. Add each variable with Name and Value
7. Click **Save**
8. **Restart** the Node.js application

---

## Verifying Your Setup

After deployment, check the health endpoint:

```
GET https://your-backend-url.com/api/health-db
```

Expected response:
```json
{
  "status": "ok",
  "environment": "production",
  "db": {
    "state": "connected",
    "connected": true
  },
  "env_status": {
    "mongo_uri": "configured",
    "jwt_secret": "configured",
    "client_url": "configured",
    "cloudinary": "configured",
    "smtp": "configured"
  }
}
```

If any value shows `"missing"`, you need to add it in hPanel.

---

## Files Modified

The following files were updated to support Hostinger Cloud:

| File | Change |
|------|--------|
| `server.js` | Conditional dotenv loading, comprehensive env validation, fail-fast in production |
| `utils/emailService.js` | Removed dotenv, removed insecure fallbacks |
| `middleware/upload.js` | Removed dotenv (now centralized) |
| `seed.js` | Conditional dotenv loading |
| `scripts/migrateLegacyUsers.js` | Conditional dotenv loading |
| `scripts/normalizeCategoryName.js` | Conditional dotenv loading |
| `scripts/testAdminLogin.js` | Conditional dotenv loading |

---

## Security Improvements

1. **No hardcoded secrets**: All sensitive values come from environment variables
2. **No localhost fallbacks**: Removed `http://localhost:5173` fallbacks that could leak in production
3. **Secured health endpoint**: `/api/health-db` no longer exposes all env keys in production
4. **Fail-fast validation**: Server crashes immediately if critical vars are missing (preventing runtime errors)

---

## Troubleshooting

### Server crashes immediately
**Cause**: Missing critical environment variables  
**Fix**: Check logs for the specific missing variable, add it in hPanel

### "Session expired" errors
**Cause**: `COOKIE_DOMAIN` mismatch or missing  
**Fix**: Set `COOKIE_DOMAIN` to `.your-domain.com` (with leading dot for subdomains)

### Database not connecting
**Cause**: `MONGO_URI` not set or incorrect  
**Fix**: Verify the MongoDB connection string in hPanel

### Emails not sending
**Cause**: SMTP credentials not set  
**Fix**: Add `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` in hPanel

### File uploads failing
**Cause**: `CLOUDINARY_URL` not set  
**Fix**: Add your Cloudinary connection URL in hPanel

---

## Local Development

For local development, continue using your `.env` file as normal.
When `NODE_ENV` is not set to `production`, dotenv will load your local `.env` file.

```bash
# Start locally (uses .env file)
npm run dev

# Or explicitly set NODE_ENV
NODE_ENV=development npm run dev
```

---

## Contact

If you encounter issues after following this guide, check:
1. Hostinger logs for startup errors
2. The `/api/health-db` endpoint for configuration status
3. MongoDB Atlas connection whitelist (ensure Hostinger IP is allowed)
