'use strict';

const fs = require('fs');
const path = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────

const SPECS_DIR = path.join(__dirname, '..', 'specs');
const BASELINE_DIR = path.join(SPECS_DIR, 'baseline');
const SPEC_FILE = path.join(SPECS_DIR, 'openapi-v1.json');
const BASELINE_FILE = path.join(BASELINE_DIR, 'openapi-v1.json');

// Route patterns that must never appear in the public spec
const PRIVATE_PATTERNS = [/\/admin/i, /\/internal/i, /\/debug/i, /\/_/];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function loadSpec(filePath) {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function allOperations(spec) {
    const ops = [];
    for (const [route, methods] of Object.entries(spec.paths ?? {})) {
        for (const [method, op] of Object.entries(methods)) {
            if (method === 'parameters') continue;
            ops.push({ route, method: method.toUpperCase(), op });
        }
    }
    return ops;
}

let errors = 0;
let warnings = 0;

function fail(msg) { console.error('  ❌  ' + msg); errors++; }
function warn(msg) { console.warn('  ⚠️   ' + msg); warnings++; }
function pass(msg) { console.log('  ✅  ' + msg); }

// ─── Rule 1 + 2 + 3: documentation completeness ───────────────────────────────

function checkCompleteness(spec) {
    console.log('\n📋  Rule 1–3: Documentation completeness');
    const ops = allOperations(spec);
    if (ops.length === 0) { warn('No paths found in spec — is the spec empty?'); return; }

    for (const { route, method, op } of ops) {
        const label = `${method} ${route}`;

        if (!op.summary) {
            fail(`[MISSING SUMMARY]     ${label}`);
        }

        const codes = Object.keys(op.responses ?? {});
        if (!codes.some((c) => c.startsWith('2'))) {
            fail(`[NO 2xx RESPONSE]     ${label}`);
        }
        if (!codes.some((c) => !c.startsWith('2'))) {
            fail(`[NO ERROR RESPONSE]   ${label}  — add at least one 4xx/5xx response`);
        }
    }
    if (errors === 0) pass(`All ${ops.length} operations are fully documented`);
}

// ─── Rule 4: breaking-change detection ────────────────────────────────────────

function checkBreakingChanges(baseline, current) {
    console.log('\n🔍  Rule 4: Breaking-change detection');
    if (!baseline) {
        pass('No baseline found — first run. Skipping breaking-change check.');
        return;
    }

    const breaking = [];

    // Removed paths
    for (const route of Object.keys(baseline.paths ?? {})) {
        if (!current.paths?.[route]) {
            breaking.push(`[REMOVED PATH]          ${route}`);
        }
    }

    // Removed methods
    for (const [route, methods] of Object.entries(baseline.paths ?? {})) {
        for (const method of Object.keys(methods)) {
            if (method === 'parameters') continue;
            if (!current.paths?.[route]?.[method]) {
                breaking.push(`[REMOVED METHOD]        ${method.toUpperCase()} ${route}`);
            }
        }
    }

    // New required fields in request bodies
    for (const [route, methods] of Object.entries(baseline.paths ?? {})) {
        for (const [method, op] of Object.entries(methods)) {
            if (method === 'parameters') continue;
            const baseRequired = op?.requestBody?.content?.['application/json']?.schema?.required ?? [];
            const currRequired =
                current.paths?.[route]?.[method]?.requestBody?.content?.['application/json']?.schema?.required ?? [];

            for (const field of currRequired) {
                if (!baseRequired.includes(field)) {
                    breaking.push(`[NEW REQUIRED FIELD]    ${method.toUpperCase()} ${route} → body.${field}`);
                }
            }
        }
    }

    if (breaking.length === 0) {
        pass('No breaking changes vs baseline');
        return;
    }

    const baseVer = baseline.info?.version ?? '?';
    const currVer = current.info?.version ?? '?';

    if (baseVer === currVer) {
        console.error(`\n  Breaking changes detected WITHOUT a version bump (${baseVer}):`);
        breaking.forEach((b) => fail(b));
        console.error('\n  Bump the API version in src/main.ts and update CHANGELOG.md.\n');
    } else {
        console.warn(`\n  Breaking changes detected with version bump (${baseVer} → ${currVer}):`);
        breaking.forEach((b) => warn(b));
        pass('Version was bumped — breaking changes are allowed');
    }
}

// ─── Rule 5: private route leakage ────────────────────────────────────────────

function checkPrivateLeakage(spec) {
    console.log('\n🔐  Rule 5: Private route leakage');
    const leaked = Object.keys(spec.paths ?? {}).filter((route) =>
        PRIVATE_PATTERNS.some((p) => p.test(route)),
    );
    if (leaked.length > 0) {
        leaked.forEach((r) => fail(`[PRIVATE ROUTE EXPOSED] ${r}`));
    } else {
        pass('No private routes exposed in public spec');
    }
}

// ─── Bonus: sensitive field names in examples ─────────────────────────────────

function checkSensitiveFields(spec) {
    console.log('\n🛡️   Bonus: Sensitive field names in examples');
    const raw = JSON.stringify(spec).toLowerCase();
    const sensitive = ['private_key', 'mnemonic', 'seed_phrase', 'secret_key'];
    const found = sensitive.filter((s) => raw.includes(s));
    if (found.length > 0) {
        found.forEach((f) => warn(`Potentially sensitive field "${f}" found in spec`));
    } else {
        pass('No sensitive field names detected');
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

console.log('\n🔒  Stellara CI Contract Guard\n' + '─'.repeat(50));

const spec = loadSpec(SPEC_FILE);
if (!spec) {
    console.error(`❌  Spec not found at ${SPEC_FILE}`);
    console.error('    Run:  npm run spec:generate\n');
    process.exit(1);
}

const baseline = loadSpec(BASELINE_FILE);

checkCompleteness(spec);
checkBreakingChanges(baseline, spec);
checkPrivateLeakage(spec);
checkSensitiveFields(spec);

console.log('\n' + '─'.repeat(50));
if (errors > 0) {
    console.error(`\n💥  Contract guard FAILED  (${errors} error(s), ${warnings} warning(s))\n`);
    process.exit(1);
}
if (warnings > 0) {
    console.warn(`\n⚠️   Contract guard passed with ${warnings} warning(s)\n`);
} else {
    console.log('\n✅  Contract guard passed — all rules satisfied\n');
}

// Save current spec as the new baseline for the next run
fs.mkdirSync(BASELINE_DIR, { recursive: true });
fs.writeFileSync(BASELINE_FILE, JSON.stringify(spec, null, 2));
console.log('📌  Baseline updated →', BASELINE_FILE);