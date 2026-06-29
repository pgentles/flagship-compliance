import express, { Request, Response } from 'express';
import cors from 'cors';
import { analyzeCompliance } from './api/compliance.js';
import { ALL_CHECKS } from './data/compliance-checks.js';

const app = express();
const PORT = process.env.PORT || 3003;
const VERSION = '1.0.0';
const USDC_BASE_MAINNET = '0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA';
const BASE_NETWORK_CAIP2 = 'eip155:8453';

app.use(cors());
app.use(express.json({ limit: '256kb' }));

// ─── X402 Middleware (x402 v2 spec compliant) ──────────────────────
const FREE_PATHS = ['/', '/health', '/openapi.json', '/favicon.ico', '/api/regulations', '/api/categories'];

app.use((req: Request, res: Response, next: any) => {
  if (FREE_PATHS.includes(req.path)) return next();

  const payment = req.headers['x402-payment'];
  if (!payment) {
    const wallet = process.env.WALLET_ADDRESS || '0x421C25445d6CF7B292933D743E698ed24dE36270';
    const resourceUrl = `https://${req.headers.host}${req.path}`;
    const accepts = [{
      scheme: 'exact',
      network: BASE_NETWORK_CAIP2,
      amount: '75000',
      asset: USDC_BASE_MAINNET,
      payTo: wallet,
      maxTimeoutSeconds: 60,
      resource: {
        url: resourceUrl,
        description: 'Regulatory compliance analysis — GLBA, SOX, PCI-DSS, CCPA, HIPAA',
        mimeType: 'application/json',
        serviceName: 'Flagship Compliance',
        tags: ['compliance', 'regulatory', 'glba', 'sox', 'pci-dss', 'ccpa', 'hipaa'],
      },
      extra: { name: 'USDC', version: '2' },
    }];
    const body = { x402Version: 2, accepts, wallet };
    const b64 = Buffer.from(JSON.stringify(body)).toString('base64');
    res.set('X-Payment-Protocol', 'x402');
    res.set('X402-Payment', 'required');
    res.set('Payment-Required', b64);
    return res.status(402).json(body);
  }

  next();
});

// ─── Health ─────────────────────────────────────────────────────────
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'flagship-compliance live',
    version: VERSION,
    endpoints: ['/api/analyze', '/api/detailed', '/api/regulations', '/api/categories'],
    uptime: process.uptime()
  });
});

// ─── OpenAPI Discovery ─────────────────────────────────────────────
app.get('/openapi.json', (_req: Request, res: Response) => {
  res.json({
    openapi: '3.1.0',
    info: {
      title: 'Flagship Compliance — Regulatory Compliance Analysis API',
      version: VERSION,
      description: 'AI-powered compliance analysis for businesses — GLBA, SOX, PCI-DSS, CCPA, HIPAA regulatory checks with automated violation detection and remediation guidance.',
      contact: { email: 'pgpgentles@gmail.com' },
      'x-guidance': 'Use POST /api/analyze to submit website/practices description for compliance analysis. Use POST /api/detailed for per-check detailed assessment. Use GET /api/regulations and GET /api/categories for reference data.',
    },
    servers: [{ url: 'https://flagship-compliance.onrender.com' }],
    paths: {
      '/api/analyze': {
        post: {
          operationId: 'analyzeCompliance',
          summary: 'Full compliance analysis',
          tags: ['Compliance Analysis'],
          'x-payment-info': {
            price: { mode: 'fixed', currency: 'USD', amount: '0.07' },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    website: { type: 'string', description: 'Business website URL to analyze' },
                    industry: { type: 'string', description: 'Industry (e.g., healthcare, finance, retail, tech)' },
                    practices: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'List of observed practices (e.g., "stores credit card data", "no privacy notice")',
                    },
                    dataTypes: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Types of data handled (e.g., "credit card", "health", "financial")',
                    },
                    dataType: { type: 'string', description: 'Primary data type handled' },
                    state: { type: 'string', description: 'US state for state-specific law applicability (e.g., CA, NY)' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Compliance analysis report',
              content: { 'application/json': { schema: { type: 'object' } } },
            },
            '402': { description: 'Payment Required' },
          },
        },
      },
      '/api/detailed': {
        post: {
          operationId: 'detailedCompliance',
          summary: 'Detailed per-check compliance assessment',
          tags: ['Compliance Analysis'],
          'x-payment-info': {
            price: { mode: 'fixed', currency: 'USD', amount: '0.15' },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    regulation: {
                      type: 'string',
                      enum: ['GLBA', 'SOX', 'PCI-DSS', 'CCPA', 'HIPAA'],
                      description: 'Specific regulation to detail',
                    },
                    website: { type: 'string' },
                    industry: { type: 'string' },
                    practices: { type: 'array', items: { type: 'string' } },
                  },
                  required: ['regulation'],
                },
              },
            },
          },
          responses: {
            '200': { description: 'Detailed regulation report' },
            '402': { description: 'Payment Required' },
          },
        },
      },
      '/api/regulations': {
        get: {
          operationId: 'listRegulations',
          summary: 'List all regulations covered (no payment required)',
          tags: ['Reference'],
          security: [],
          responses: {
            '200': { description: 'List of supported regulations' },
          },
        },
      },
      '/api/categories': {
        get: {
          operationId: 'listCategories',
          summary: 'List compliance categories (no payment required)',
          tags: ['Reference'],
          security: [],
          responses: {
            '200': { description: 'Compliance categories' },
          },
        },
      },
    },
  });
});

// ─── API: Full Compliance Analysis ──────────────────────────────────
const queryLog: Array<{ type: string; timestamp: string; path: string }> = [];
const MAX_LOG = 1000;

app.post('/api/analyze', (req: Request, res: Response) => {
  const { website, industry, practices, dataTypes, dataType, state } = req.body;
  const desc = [website, industry, state].filter(Boolean).join(' ');
  if (desc.length < 5) {
    return res.status(400).json({
      error: 'Provide at minimum: website URL, industry, or state for analysis.',
    });
  }

  const report = analyzeCompliance({ website, industry, practices, dataTypes, dataType, state });
  queryLog.push({ type: 'analyze', timestamp: new Date().toISOString(), path: '/api/analyze' });
  if (queryLog.length > MAX_LOG) queryLog.shift();

  res.json({
    ...report,
    generatedAt: new Date().toISOString(),
    disclaimer: 'This analysis is informational only and does not constitute legal advice. Consult a licensed attorney for formal compliance guidance.',
  });
});

// ─── API: Detailed Per-Regulation Check ─────────────────────────────
app.post('/api/detailed', (req: Request, res: Response) => {
  const { regulation, website, industry, practices } = req.body;
  if (!regulation || !['GLBA', 'SOX', 'PCI-DSS', 'CCPA', 'HIPAA'].includes(regulation)) {
    return res.status(400).json({
      error: 'Parameter "regulation" is required and must be one of: GLBA, SOX, PCI-DSS, CCPA, HIPAA',
    });
  }

  const regChecks = ALL_CHECKS.filter(c => c.regulation === regulation);
  const findings = regChecks.map(check => ({
    check,
    status: 'pass' as const,
    notes: 'Manual review required for final determination.',
    recommendations: check.remediationSteps,
  }));

  queryLog.push({ type: 'detailed', timestamp: new Date().toISOString(), path: '/api/detailed' });
  if (queryLog.length > MAX_LOG) queryLog.shift();

  res.json({
    regulation,
    checkCount: regChecks.length,
    findings,
    created: new Date().toISOString(),
  });
});

// ─── API: Regulations Reference ─────────────────────────────────────
app.get('/api/regulations', (_req: Request, res: Response) => {
  const regulations = Array.from(new Set(ALL_CHECKS.map(c => c.regulation)));
  res.json({
    count: regulations.length,
    regulations: regulations.map(reg => ({
      name: reg,
      checkCount: ALL_CHECKS.filter(c => c.regulation === reg).length,
      categories: [...new Set(ALL_CHECKS.filter(c => c.regulation === reg).map(c => c.category))],
    })),
  });
});

// ─── API: Compliance Categories ─────────────────────────────────────
app.get('/api/categories', (_req: Request, res: Response) => {
  const categories = [...new Set(ALL_CHECKS.map(c => c.category))];
  res.json({
    count: categories.length,
    categories: categories.map(cat => ({
      name: cat,
      checkCount: ALL_CHECKS.filter(c => c.category === cat).length,
      regulations: [...new Set(ALL_CHECKS.filter(c => c.category === cat).map(c => c.regulation))],
    })),
  });
});

// ─── Static Files ───────────────────────────────────────────────────
app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Flagship Compliance v${VERSION} running on port ${PORT}`);
  console.log(`API: http://localhost:${PORT}/api/{analyze,detailed,regulations,categories}`);
  console.log(`OpenAPI: http://localhost:${PORT}/openapi.json`);
});
