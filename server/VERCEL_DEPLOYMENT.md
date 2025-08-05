# Vercel Deployment Instructions

## Environment Variables Setup

To fix the database connection issues, you need to set environment variables in your Vercel dashboard:

### 1. Go to Vercel Dashboard
- Visit https://vercel.com/dashboard
- Select your project (coinancebac)
- Go to Settings > Environment Variables

### 2. Add These Environment Variables

| Variable Name | Value |
|--------------|--------|
| `DATABASE_URL` | `postgres://neondb_owner:npg_GUnkL7AYE5lw@ep-autumn-feather-a2hf171v-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require` |
| `SECRET_KEY` | `BX74jvC8NsfkGh0LsLZm49O1i8Dz9t57` |
| `PORT` | `3001` |
| `FRONTEND_URL` | `https://dashboard.coinance.co` |
| `SMTP_HOST` | `smtp.hostinger.com` |
| `SMTP_PORT` | `465` |
| `SMTP_USER` | `support@coinance.co` |
| `SMTP_PASSWORD` | `Zoja25##` |

### 3. Environment Settings
- Set environment for: **All Environments** (Production, Preview, Development)
- This ensures the variables are available in all deployment environments

### 4. Redeploy
After adding the environment variables:
- Go to Deployments tab
- Click the three dots (...) on the latest deployment
- Select "Redeploy"

## Troubleshooting

If you still get connection errors:
1. Check that all environment variables are set correctly
2. Ensure DATABASE_URL exactly matches the Neon connection string
3. Verify the Neon database is active and accessible

## Alternative Variable Names
The system will also check these alternative names:
- `POSTGRES_URL`
- `POSTGRESQL_URL`
- `DB_URL`
- `NEON_DATABASE_URL` 