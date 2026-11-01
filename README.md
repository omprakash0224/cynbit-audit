# Cynbit Technologies - Backend Technical Assessment Submission

**Applicant:** Om Prakash Samal  
**Position:** Backend Developer Intern  
**Target:** [Cynbit Technologies (https://www.cynbit.in/)](https://www.cynbit.in/)  
**Submission Date:** November 2026  

---

## Deliverables Overview

This repository contains the complete assessment deliverables requested by Aria and the Cynbit Talent Acquisition team:

1. **[CYNBIT_BACKEND_AUDIT_REPORT.md](file:///d:/cynbit-audit/CYNBIT_BACKEND_AUDIT_REPORT.md)**
   - **Executive Summary:** Overview of audit scope, architecture, and findings.
   - **Observable Architecture:** Vercel Edge hosting (`bom1`), Next.js App Router RSC streaming, subdomain topology (`portal.cynbit.in`), and Server Action RPC mechanisms.
   - **Empirical Sources & Evidence:** Verifiable source citations for every claim (HTTP header dumps, decompiled Webpack chunk ASTs, Server Action IDs, and robots.txt).
   - **Google Lighthouse 13.6.0 Benchmark:** Core Web Vitals audit (Performance: 70, Best Practices: 100, SEO: 100), network round-trip latencies, TTFB (26ms–30ms), and root cause analysis of the 10.7s LCP hydration delay.
   - **OWASP Top 10 & API Security Threat Assessment:** Category-by-category threat model evaluating A01 through A10 (Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Auth Failures, etc.).
   - **Security & Performance Findings:** Categorized findings (SEC-01 through SEC-06, PERF-01 through PERF-03).
   - **Privacy & Data Handling Analysis:** Duplicate candidate enumeration mitigation and payload validation.
   - **Mermaid Architecture & Sequence Diagrams:** Visualizing request lifecycles and background queue decoupling.

2. **Technical Improvement Implementations (`src/`):**
   - **[src/middleware.ts](file:///d:/cynbit-audit/src/middleware.ts):** Next.js Edge Middleware injecting CSP, X-Frame-Options (DENY), nosniff, Referrer-Policy, stripping `X-Powered-By`, and scoping CORS.
   - **[src/lib/validations/candidateSchema.ts](file:///d:/cynbit-audit/src/lib/validations/candidateSchema.ts):** Zod schemas for candidate application data, nested education data, URL protocol validation, and contact inquiries.
   - **[src/actions/candidateApplication.ts](file:///d:/cynbit-audit/src/actions/candidateApplication.ts):** Hardened Server Action with IP rate limiting, privacy-preserving duplicate handling, and async queue decoupling.
   - **[src/lib/auth/portalAuth.ts](file:///d:/cynbit-audit/src/lib/auth/portalAuth.ts):** Modernized JWT session authentication with RBAC and `httpOnly` secure cookies replacing single shared security keys.

3. **Empirical Artifacts & Diagnostic Tools:**
   - **[src/scripts/owaspCheck.mjs](file:///d:/cynbit-audit/src/scripts/owaspCheck.mjs):** Automated passive OWASP security inspection script for evaluating defensive headers, CORS, and information disclosure across endpoints.
   - **[lighthouse-report.json](file:///d:/cynbit-audit/lighthouse-report.json):** Full raw JSON report from Google Lighthouse 13.6.0 testing run.

---

## Repository Structure

```tree
d:\cynbit-audit
├── CYNBIT_BACKEND_AUDIT_REPORT.md     # Primary Assessment Report (with Lighthouse, OWASP & Sources)
├── lighthouse-report.json             # Raw Lighthouse 13.6.0 Audit Result Data
├── README.md                          # Project & Submission Overview
└── src
    ├── middleware.ts                  # Edge Security Headers & CORS Middleware
    ├── actions
    │   └── candidateApplication.ts    # Re-engineered Privacy-Preserving Server Action
    ├── lib
    │   ├── auth
    │   │   └── portalAuth.ts          # RBAC & Secure Cookie Session Auth
    │   └── validations
    │       └── candidateSchema.ts     # Zod Schemas & Input Sanitization
    └── scripts
        └── owaspCheck.mjs             # Automated Passive OWASP Security Scanner
```

---

## Submission Checklist for Aria / Cynbit TA

- [x] **Backend Technical Audit Report:** Complete with deep architectural insights, RPC payload analysis, and edge infrastructure inspection.
- [x] **OWASP Top 10 Security Assessment:** Full compliance matrix and threat modeling with automated passive scanner script.
- [x] **Empirical Verification Sources:** Complete header dumps, bundle hashes, server action IDs, and deobfuscated code references.
- [x] **Speed & Performance Benchmarks:** Full Google Lighthouse 13.6.0 run and multi-route cURL latency analysis.
- [x] **Security & Performance Findings:** Categorized by severity, risk analysis, and impact.
- [x] **Recommended Improvements & Code Snippets:** Ready-to-review TypeScript code implementing every proposed architectural fix.
- [x] **Strict Compliance:** 100% passive, zero disruption, no invasive or unauthorized attacks.
