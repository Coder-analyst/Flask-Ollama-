# Vercel Deployment Setup

## 🚀 Deploy Frontend to Vercel with ngrok Backend

Your frontend is deployed on Vercel, and it needs to connect to your local Ollama through ngrok.

### Step 1: Set Environment Variable in Vercel

#### Option A: Using Vercel Dashboard (Recommended)

1. Go to your Vercel project dashboard
2. Click on **Settings** tab
3. Click on **Environment Variables** in the sidebar
4. Add a new environment variable:
   - **Name**: `VITE_API_URL`
   - **Value**: `https://76993c30536d.ngrok-free.app/api`
   - **Environment**: Select all (Production, Preview, Development)
5. Click **Save**
6. **Redeploy** your project for changes to take effect

#### Option B: Using Vercel CLI

```bash
# Install Vercel CLI if you haven't
npm i -g vercel

# Set the environment variable
vercel env add VITE_API_URL

# When prompted, enter: https://76993c30536d.ngrok-free.app/api
# Select: Production, Preview, Development (all)

# Redeploy
vercel --prod
```

### Step 2: Verify Configuration

After redeploying, your Vercel frontend will connect to:
```
https://76993c30536d.ngrok-free.app/api
```

Which tunnels to your local Ollama at:
```
http://localhost:11434
```

### Step 3: Test the Connection

1. Open your Vercel app URL (e.g., `https://your-app.vercel.app`)
2. Try sending a message
3. Check if it connects to your local Ollama through ngrok

### 🔄 Architecture Flow

```
User Browser
    ↓
Vercel Frontend (https://your-app.vercel.app)
    ↓
ngrok Tunnel (https://76993c30536d.ngrok-free.app)
    ↓
Local Ollama (http://localhost:11434)
```

### ⚠️ Important Notes

1. **Keep ngrok running**: Your ngrok tunnel must be active for this to work
2. **ngrok URL changes**: Free ngrok URLs change when you restart ngrok
3. **Update Vercel env**: When ngrok URL changes, update `VITE_API_URL` in Vercel
4. **CORS**: Make sure your backend allows requests from your Vercel domain

### 🔧 Troubleshooting

#### Issue: "Failed to fetch" or CORS errors

Update your backend CORS configuration in `backend/server.js`:

```javascript
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://your-app.vercel.app',  // Add your Vercel URL
    /\.vercel\.app$/  // Allow all Vercel preview deployments
  ]
}));
```

#### Issue: ngrok URL expired

1. Restart ngrok: `ngrok http 11434`
2. Get new URL
3. Update `VITE_API_URL` in Vercel dashboard
4. Redeploy

### 💡 Alternative: Deploy Backend Too

For a permanent solution without ngrok:

1. Deploy backend to Railway/Render/Fly.io
2. Set `OLLAMA_URL` to your deployed Ollama instance
3. Update Vercel's `VITE_API_URL` to your deployed backend URL

This eliminates the need for ngrok and provides a stable connection.
