# Ollama Chat UI

A ChatGPT-style frontend for your local Ollama installation with support for text chat, audio recording, and file uploads (PDF, DOCX, CSV, TXT, images).

## Features

- 💬 Text chat with Ollama models
- 🎤 Audio recording → automatic transcription
- 📎 File uploads (PDF, DOCX, CSV, TXT, images with OCR)
- 🔄 Model selection
- 📱 Responsive ChatGPT-style UI

## Prerequisites

- Node.js 18+
- Ollama installed and running locally
- At least one Ollama model pulled (e.g., `ollama pull llama3`)

## Installation

```bash
# Install all dependencies
npm run install:all
```

## Usage

```bash
# Start both frontend and backend
npm run dev
```

- Frontend: http://localhost:3000
- Backend: http://localhost:5000

## How It Works

1. **Text Chat**: Type and send messages directly to Ollama
2. **Audio**: Click mic icon to record, stop to transcribe and send
3. **Files**: Click paperclip to upload PDF, DOCX, CSV, TXT, or images
4. **Model Selection**: Choose from available Ollama models in the dropdown

## File Support

- **PDF**: Text extraction
- **DOCX**: Text extraction
- **CSV**: Parsed as JSON
- **TXT**: Direct text
- **Images**: OCR with Tesseract

## Architecture

```
frontend/  → React + Vite + Tailwind
backend/   → Node.js + Express + Ollama CLI
```

Backend processes files, calls Ollama via CLI, and returns responses to the frontend.

---

## 🌐 Expose Ollama to the Internet (Using ngrok)

Want to access your local Ollama from anywhere? Use ngrok to create a public tunnel.

⚠️ **Warning**: This exposes your local Ollama to the internet. Only use for testing/personal use.

### Step-by-Step Setup

#### 1. Install ngrok
Download from: https://ngrok.com/download

#### 2. Expose Ollama Port
Ollama runs on `localhost:11434` by default. Run:

```bash
ngrok http 11434
```

#### 3. Get Your Public URL
ngrok will display a public URL like:
```
https://f3a2-103-22-88-64.ngrok-free.app
```

#### 4. Update Frontend Configuration
In your Vercel frontend or local `.env`, set the backend URL:

```env
VITE_BACKEND_URL=https://f3a2-xxx.ngrok-free.app
```

#### 5. Update Backend to Use ngrok URL
Modify `backend/server.js` to use the ngrok URL instead of localhost:

```javascript
// Replace localhost with your ngrok URL
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';

// In queryOllama function:
const response = await fetch(`${OLLAMA_URL}/api/generate`, {
  // ...
});
```

### 🎉 Done!
Now anyone can access your Ollama through the ngrok link.

### ⚠️ Important Notes
- **Free ngrok links expire** when you restart ngrok (unless you have a paid plan)
- **Security**: Your Ollama is publicly accessible - use with caution
- **Performance**: Requests go through ngrok's servers, adding latency
- **Keep ngrok running**: The tunnel only works while ngrok is active

### Alternative: Deploy Backend
For a permanent solution, consider deploying your backend to:
- Railway
- Render
- Fly.io
- DigitalOcean

Then point your frontend to the deployed backend URL.
