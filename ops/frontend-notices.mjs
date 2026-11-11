// Preserve notices for installed frontend packages alongside the built bundle.
import fs from 'node:fs';
import path from 'node:path';

const ui = process.cwd();
const lock = JSON.parse(fs.readFileSync(path.join(ui, 'package-lock.json'), 'utf8'));
const sections = ['Frontend third-party package notices\nGenerated from the installed npm packages.\n'];
for (const relative of Object.keys(lock.packages).sort()) {
  if (!relative.startsWith('node_modules/')) continue;
  const directory = path.join(ui, relative);
  if (!fs.existsSync(directory)) continue; // Optional packages for other platforms.
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  const licenses = fs.readdirSync(directory).filter(name => /^(licen[cs]e|copying|notice)(\.|-|$)/i.test(name)
    && fs.statSync(path.join(directory, name)).isFile());
  sections.push(`\n${'='.repeat(72)}\n${metadata.name} ${metadata.version}\nLicense: ${JSON.stringify(metadata.license || 'See upstream package')}\n`);
  for (const name of licenses.sort()) {
    sections.push(`\n--- ${name} ---\n${fs.readFileSync(path.join(directory, name), 'utf8')}\n`);
  }
}
const destination = path.resolve(ui, '../app/static/third-party-notices.txt');
fs.writeFileSync(destination, sections.join(''), 'utf8');
console.log('Wrote frontend third-party notices.');
