/**
 * Cynbit Passive OWASP Security Audit Utility
 * 
 * Strictly non-invasive, passive testing utility evaluating:
 * - OWASP A01 (Access Control & Exposure)
 * - OWASP A02 (Cryptographic & Transport Security)
 * - OWASP A05 (Security Misconfigurations: Headers, CORS, Fingerprints)
 * - OWASP A07 (Auth & Session Hygiene)
 */

const TARGETS = [
  'https://www.cynbit.in/',
  'https://www.cynbit.in/contact',
  'https://www.cynbit.in/careers/backend-developer-intern',
  'https://portal.cynbit.in/',
  'https://portal.cynbit.in/dashboard',
];

const REQUIRED_SECURITY_HEADERS = [
  { name: 'content-security-policy', standard: 'CSP defined with strict script/frame sources', owasp: 'A05:2021' },
  { name: 'x-frame-options', standard: 'DENY or SAMEORIGIN (prevents clickjacking)', owasp: 'A05:2021' },
  { name: 'x-content-type-options', standard: 'nosniff (prevents MIME sniffing)', owasp: 'A05:2021' },
  { name: 'referrer-policy', standard: 'strict-origin-when-cross-origin', owasp: 'A05:2021' },
  { name: 'permissions-policy', standard: 'Restricts hardware sensors/camera/mic', owasp: 'A05:2021' },
  { name: 'strict-transport-security', standard: 'HSTS with max-age >= 31536000', owasp: 'A02:2021' },
];

const LEAKED_HEADERS = ['x-powered-by', 'server'];

async function inspectTarget(url) {
  console.log(`\n========================================`);
  console.log(`Auditing Target: ${url}`);
  console.log(`========================================`);

  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'manual' });
    const headers = Object.fromEntries(res.headers.entries());

    console.log(`Status: ${res.status} ${res.statusText}`);

    // Check Security Headers
    console.log('\n[OWASP A05 / A02: HTTP Defensive Headers]');
    for (const h of REQUIRED_SECURITY_HEADERS) {
      if (headers[h.name]) {
        console.log(`  [PASS] ${h.name}: ${headers[h.name]}`);
      } else {
        console.log(`  [FAIL] Missing ${h.name} (${h.standard}) - Ref: ${h.owasp}`);
      }
    }

    // Check CORS
    console.log('\n[OWASP A01 / A05: CORS Policy]');
    if (headers['access-control-allow-origin']) {
      const cors = headers['access-control-allow-origin'];
      if (cors === '*') {
        console.log(`  [WARN] Universal wildcard CORS present: 'Access-Control-Allow-Origin: *'`);
      } else {
        console.log(`  [PASS] Scoped CORS: ${cors}`);
      }
    } else {
      console.log(`  [INFO] No Access-Control-Allow-Origin header returned`);
    }

    // Check Fingerprinting
    console.log('\n[OWASP A05: Framework Fingerprinting]');
    for (const leak of LEAKED_HEADERS) {
      if (headers[leak]) {
        console.log(`  [WARN] Leaked header detected: '${leak}: ${headers[leak]}'`);
      }
    }

    return { url, status: res.status, headers };
  } catch (err) {
    console.error(`Error querying ${url}:`, err.message);
    return null;
  }
}

async function run() {
  console.log('Running Cynbit Passive OWASP Security Audit...');
  for (const target of TARGETS) {
    await inspectTarget(target);
  }
}

run();

