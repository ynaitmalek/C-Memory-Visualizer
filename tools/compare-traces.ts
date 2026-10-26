/**
 * Phase 1 stub of the engine-vs-GDB comparison (§6). It only checks that every example has a
 * well-formed GDB trace. The browser engine does not exist yet, so NO engine comparison happens;
 * this is replaced in phase 3.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(import.meta.dirname, '..', 'src', 'examples');
let failed = false;
for (const f of readdirSync(dir).filter((n) => n.endsWith('.c'))) {
  const name = f.slice(0, -2);
  try {
    const t = JSON.parse(readFileSync(join(dir, `${name}.gdb-trace.json`), 'utf8'));
    if (t.status !== 'ok' || !Array.isArray(t.steps) || t.steps.length === 0) throw new Error(`bad trace (status=${t.status})`);
    console.log(`ok   ${name}: ${t.steps.length} GDB steps`);
  } catch (e) {
    failed = true;
    console.error(`FAIL ${name}: ${(e as Error).message}`);
  }
}
console.log('NOTE: browser engine not implemented yet; engine-vs-GDB comparison skipped.');
process.exit(failed ? 1 : 0);
