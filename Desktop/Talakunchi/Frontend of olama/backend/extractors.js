import fs from 'fs/promises';
import pdf from 'pdf-parse';
import mammoth from 'mammoth';
import csvParser from 'csv-parser';
import { createReadStream } from 'fs';
import { createWorker } from 'tesseract.js';

export async function extractText(filePath, mimeType) {
  const buffer = await fs.readFile(filePath);

  // PDF
  if (mimeType === 'application/pdf') {
    const data = await pdf(buffer);
    return data.text;
  }

  // DOCX
  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    const result = await mammoth.extractRawText({ buffer });
    return result.value;
  }

  // CSV
  if (mimeType === 'text/csv') {
    return new Promise((resolve, reject) => {
      const rows = [];
      createReadStream(filePath)
        .pipe(csvParser())
        .on('data', (row) => rows.push(row))
        .on('end', () => resolve(JSON.stringify(rows, null, 2)))
        .on('error', reject);
    });
  }

  // Images (OCR)
  if (mimeType.startsWith('image/')) {
    const worker = await createWorker('eng');
    const { data: { text } } = await worker.recognize(buffer);
    await worker.terminate();
    return text;
  }

  // Plain text
  if (mimeType.startsWith('text/')) {
    return buffer.toString('utf-8');
  }

  throw new Error('Unsupported file type');
}
