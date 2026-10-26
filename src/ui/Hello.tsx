import trace from '../examples/factorial.gdb-trace.json';

/** Phase-1 smoke page: proves the build bundles the CI-generated GDB trace. */
export default function Hello() {
  return (
    <main className="mx-auto max-w-xl p-8 font-sans">
      <h1 className="text-2xl font-bold">Visualiseur mémoire C</h1>
      <p className="mt-2 text-slate-600">
        Trace chargée : <code>{trace.program.name}</code> — {trace.steps.length} étapes, source{' '}
        <code>{trace.source}</code>.
      </p>
    </main>
  );
}
