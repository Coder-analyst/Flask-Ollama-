import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { extractText } from './extractors.js';

const execAsync = promisify(exec);
const app = express();
const upload = multer({ dest: 'uploads/' });

// CORS configuration - allow Vercel and local development
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    /\.vercel\.app$/  // Allow all Vercel deployments
  ],
  credentials: true
}));
app.use(express.json());

// Ollama URL - can be localhost or ngrok URL
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';

// Query Ollama using HTTP API
async function queryOllama(prompt, model = 'llama3') {
  try {
    const response = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: model,
        prompt: prompt,
        stream: false
      })
    });

    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data.response;
  } catch (error) {
    throw new Error(`Ollama error: ${error.message}`);
  }
}

// Main chat endpoint
app.post('/api/query', upload.single('file'), async (req, res) => {
  try {
    let prompt = req.body.prompt || '';
    const model = req.body.model || 'llama3';
    let metadata = { type: 'text' };

    // Handle file upload
    if (req.file) {
      const filePath = req.file.path;
      const originalName = req.file.originalname;
      
      try {
        const fileContent = await extractText(filePath, req.file.mimetype);
        prompt += `\n\nFile: ${originalName}\nContent:\n${fileContent}`;
        metadata = { type: 'file', filename: originalName };
      } catch (error) {
        return res.status(400).json({ error: `Failed to process file: ${error.message}` });
      } finally {
        // Cleanup uploaded file
        await fs.unlink(filePath).catch(() => {});
      }
    }

    if (!prompt.trim()) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // Query Ollama
    const response = await queryOllama(prompt, model);

    res.json({
      response,
      metadata,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get available models
app.get('/api/models', async (req, res) => {
  try {
    const response = await fetch(`${OLLAMA_URL}/api/tags`);
    const data = await response.json();
    const models = data.models.map(m => m.name);
    res.json({ models });
  } catch (error) {
    res.json({ models: ['llama3'] });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
  console.log(`Using Ollama at: ${OLLAMA_URL}`);
});
