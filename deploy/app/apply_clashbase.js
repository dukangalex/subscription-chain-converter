// Runner: apply the bundled override script (mihomoScript.js) to a base
// config JSON and write the resulting config JSON.
// Usage: node apply_clashbase.js <script.js> <base.json> <out.json>
const fs = require('fs');
const vm = require('vm');
const [scriptPath, inPath, outPath] = process.argv.slice(2);
const src = fs.readFileSync(scriptPath, 'utf8');
const base = JSON.parse(fs.readFileSync(inPath, 'utf8'));
const ctx = vm.createContext({ console });
vm.runInContext(src, ctx);
const out = vm.runInContext('main', ctx)(base);
fs.writeFileSync(outPath, JSON.stringify(out));
