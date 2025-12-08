# Quick Start Guide

## 🎯 Your Current Setup

**ngrok URL**: `https://76993c30536d.ngrok-free.app`

### For Vercel Deployment

1. **Add Environment Variable in Vercel Dashboard**:
   - Go to: Project Settings → Environment Variables
   - Add: `VITE_API_URL` = `https://76993c30536d.ngrok-free.app/api`
   - Save and redeploy

2. **Keep ngrok running locally**:
   ```bash
   ngrok http 11434
   ```

3. **Start your backend locally**:
   ```bash
   cd backend
   npm start
   ```

### For Local Development

1. **Start backend**:
   ```bash
   cd backend
   npm start
   ```

2. **Start frontend**:
   ```bash
   cd frontend
   npm run dev
   ```

## 📋 Configuration Files Created

- ✅ `backend/.env` - Backend configured with ngrok URL
- ✅ `frontend/.env` - Frontend configured with ngrok URL
- ✅ `backend/server.js` - CORS enabled for Vercel domains
- ✅ `VERCEL_SETUP.md` - Detailed Vercel setup instructions

## 🔗 Connection Flow

```
Vercel Frontend → ngrok Tunnel → Local Backend → Local Ollama
```

## ⚠️ Remember

- ngrok must be running for this to work
- Free ngrok URLs change on restart
- Update Vercel env variable if ngrok URL changes
