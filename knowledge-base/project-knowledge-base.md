# Flagship Compliance — Project Knowledge Base

> **Last Updated:** 2026-06-29
> **Status:** Live on Render ✅ — x402scan ✅ Registered
> **Repo:** https://github.com/pgentles/flagship-compliance
> **Live URL:** https://flagship-compliance.onrender.com

---

## 1. Executive Summary

Flagship Compliance is a regulatory compliance analysis API for AI agents. It checks documents/practices against GLBA, SOX, PCI-DSS, CCPA, and HIPAA requirements and provides gap analysis with remediation steps.

## 2. Endpoints

### Paid
| Endpoint | Price (USDC) | Input |
|----------|-------------|-------|
| POST /api/analyze | 0.07 | {document, type} |
| POST /api/detailed | 0.15 | {document, type, sections?} |

### Free
| Endpoint | Purpose |
|----------|---------|
| GET /api/regulations | List all tracked regulations |
| GET /api/categories | Compliance categories |
| GET /api/sales | Transaction count |

## 3. Compliance Checks (16 total)

- GLBA: Safeguards Rule, Privacy Rule, Pretexting
- SOX: Sections 302, 404, 802, 906
- PCI-DSS: Requirements 1-12 (summary checks)
- CCPA: Consumer rights, data handling
- HIPAA: Privacy Rule, Security Rule, Breach Notification

## 4. Architecture

Single-file Express server with x402 v2 middleware. Same pattern as all Flagship services.
