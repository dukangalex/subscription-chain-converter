const fs = require('fs');
const vm = require('vm');
const [scriptPath, inPath, overlayPath, outPath] = process.argv.slice(2);
const src = fs.readFileSync(scriptPath, 'utf8');
const base = JSON.parse(fs.readFileSync(inPath, 'utf8'));
const ctx = vm.createContext({ console });
if (overlayPath && fs.existsSync(overlayPath)) {
  ctx.overlay = JSON.parse(fs.readFileSync(overlayPath, 'utf8'));
}
vm.runInContext(src, ctx);
const out = vm.runInContext('main', ctx)(base);
fs.writeFileSync(outPath, JSON.stringify(out));
