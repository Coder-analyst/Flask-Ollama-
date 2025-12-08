import { useState, useRef, useEffect } from 'react';
import { Send, Paperclip, Mic, MicOff } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

export default function App() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [file, setFile] = useState(null);
  const [isRecording, setIsRecording] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [models, setModels] = useState(['llama3']);
  const [selectedModel, setSelectedModel] = useState('llama3');
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);

  useEffect(() => {
    fetchModels();
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function fetchModels() {
    try {
      const res = await fetch(`${API_URL}/models`);
      const data = await res.json();
      if (data.models.length > 0) {
        setModels(data.models);
        setSelectedModel(data.models[0]);
      }
    } catch (error) {
      console.error('Failed to fetch models:', error);
    }
  }

  async function sendMessage(e) {
    e?.preventDefault();
    if ((!input.trim() && !file) || isLoading) return;

    const userMessage = {
      role: 'user',
      content: input,
      file: file?.name,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);

    const formData = new FormData();
    formData.append('prompt', input);
    formData.append('model', selectedModel);
    if (file) formData.append('file', file);

    setInput('');
    setFile(null);

    try {
      const res = await fetch(`${API_URL}/query`, {
        method: 'POST',
        body: formData
      });

      const data = await res.json();

      if (res.ok) {
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: data.response,
          metadata: data.metadata,
          timestamp: data.timestamp
        }]);
      } else {
        throw new Error(data.error);
      }
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'error',
        content: `Error: ${error.message}`,
        timestamp: new Date().toISOString()
      }]);
    } finally {
      setIsLoading(false);
    }
  }

  function handleFileSelect(e) {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  }

  async function toggleRecording() {
    if (!isRecording) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorderRef.current = new MediaRecorder(stream);
        audioChunksRef.current = [];

        mediaRecorderRef.current.ondataavailable = (e) => {
          audioChunksRef.current.push(e.data);
        };

        mediaRecorderRef.current.onstop = () => {
          const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/wav' });
          const audioFile = new File([audioBlob], 'recording.wav', { type: 'audio/wav' });
          setFile(audioFile);
          stream.getTracks().forEach(track => track.stop());
        };

        mediaRecorderRef.current.start();
        setIsRecording(true);
      } catch (error) {
        alert('Microphone access denied');
      }
    } else {
      mediaRecorderRef.current?.stop();
      setIsRecording(false);
    }
  }

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b px-6 py-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Ollama Chat</h1>
        <select
          value={selectedModel}
          onChange={(e) => setSelectedModel(e.target.value)}
          className="px-3 py-1 border rounded-lg text-sm"
        >
          {models.map(model => (
            <option key={model} value={model}>{model}</option>
          ))}
        </select>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-2xl px-4 py-3 rounded-lg ${
              msg.role === 'user' ? 'bg-blue-500 text-white' :
              msg.role === 'error' ? 'bg-red-100 text-red-800' :
              'bg-white border'
            }`}>
              {msg.file && (
                <div className="text-xs opacity-75 mb-1">📎 {msg.file}</div>
              )}
              <div className="whitespace-pre-wrap">{msg.content}</div>
              <div className="text-xs opacity-50 mt-1">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-white border px-4 py-3 rounded-lg">
              <div className="flex space-x-2">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="bg-white border-t px-6 py-4">
        {file && (
          <div className="mb-2 flex items-center text-sm text-gray-600">
            <Paperclip className="w-4 h-4 mr-1" />
            {file.name}
            <button onClick={() => setFile(null)} className="ml-2 text-red-500">✕</button>
          </div>
        )}
        <form onSubmit={sendMessage} className="flex items-center space-x-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileSelect}
            className="hidden"
            accept=".pdf,.docx,.csv,.txt,image/*"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="p-2 hover:bg-gray-100 rounded-lg"
          >
            <Paperclip className="w-5 h-5" />
          </button>
          <button
            type="button"
            onClick={toggleRecording}
            className={`p-2 rounded-lg ${isRecording ? 'bg-red-500 text-white' : 'hover:bg-gray-100'}`}
          >
            {isRecording ? <MicOff className="w-5 h-5" /> : <Mic className="w-5 h-5" />}
          </button>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type a message..."
            className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            disabled={isLoading || (!input.trim() && !file)}
            className="p-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="w-5 h-5" />
          </button>
        </form>
      </div>
    </div>
  );
}
