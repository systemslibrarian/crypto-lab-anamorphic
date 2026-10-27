#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vitest = join(root, 'node_modules', '.bin', 'vitest');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const mutations = [
  {
    name: 'PRF domain separation silently changes',
    file: 'src/anamorphic.ts',
    from: "export const PRF_DOMAIN = 'CRYPTO-LAB-ANAMORPHIC-SYNC-ELGAMAL-v1';",
    to: "export const PRF_DOMAIN = 'CRYPTO-LAB-ANAMORPHIC-SYNC-ELGAMAL-v2';",
    suite: 'src/anamorphic.test.ts',
    test: 'pins HMAC-SHA-512 rejection mapping for one declared key and counter'
  },
  {
    name: 'PRF uses SHA-256 instead of the declared SHA-512',
    file: 'src/anamorphic.ts',
    from: '      sha512,\n      prfKey,',
    to: '      sha256,\n      prfKey,',
    suite: 'src/anamorphic.test.ts',
    test: 'pins HMAC-SHA-512 rejection mapping for one declared key and counter'
  },
  {
    name: 'scalar sampler truncates one more high bit',
    file: 'src/anamorphic.ts',
    from: '    bytes[0] = bytes[0]! & 0x1f; // Uniform candidate in [0, 2^253).',
    to: '    bytes[0] = bytes[0]! & 0x0f; // MUTANT: only 252 candidate bits.',
    suite: 'src/anamorphic.test.ts',
    test: 'samples exactly in the scalar field and rejects an out-of-range candidate'
  },
  {
    name: 'synchronized counter is ignored by the PRF',
    file: 'src/anamorphic.ts',
    from: '      concatBytes(utf8ToBytes(PRF_DOMAIN), u32(counter), u32(attempt))',
    to: '      concatBytes(utf8ToBytes(PRF_DOMAIN), u32(0), u32(attempt))',
    suite: 'src/anamorphic.test.ts',
    test: 'pins HMAC-SHA-512 rejection mapping for one declared key and counter'
  },
  {
    name: 'covert scalar is omitted from anamorphic randomness',
    file: 'src/anamorphic.ts',
    from: '  const randomness = mod(covert.scalar + mask);',
    to: '  const randomness = mod(mask);',
    suite: 'src/anamorphic.test.ts',
    test: 'recovers every overt/covert combination from its corresponding key view'
  },
  {
    name: 'ordinary receiver adds the ElGamal shared point',
    file: 'src/anamorphic.ts',
    from: '  return ciphertext.c1.subtract(multiplyPoint(ciphertext.c2, secretKey));',
    to: '  return ciphertext.c1.add(multiplyPoint(ciphertext.c2, secretKey));',
    suite: 'src/anamorphic.test.ts',
    test: 'round-trips every overt message through normal ElGamal'
  },
  {
    name: 'double-key receiver adds the PRF mask',
    file: 'src/anamorphic.ts',
    from: '  const candidate = ciphertext.c2.subtract(scalarPoint(mask));',
    to: '  const candidate = ciphertext.c2.add(scalarPoint(mask));',
    suite: 'src/anamorphic.test.ts',
    test: 'recovers every overt/covert combination from its corresponding key view'
  },
  {
    name: 'ciphertext serialization drops its second point',
    file: 'src/anamorphic.ts',
    from: '  return concatBytes(ciphertext.c1.toBytes(), ciphertext.c2.toBytes());',
    to: '  return concatBytes(ciphertext.c1.toBytes());',
    suite: 'src/anamorphic.test.ts',
    test: 'puts no mode or counter field into the two-point ciphertext'
  },
  {
    name: 'robustness bound omits the covert message-space size',
    file: 'src/anamorphic.ts',
    from: '  return BigInt(queries) * BigInt(COVERT_MESSAGES.length);',
    to: '  return BigInt(queries);',
    suite: 'src/anamorphic.test.ts',
    test: 'states the paper-style robustness term for the eight-symbol table'
  },
  {
    name: 'bounded covert/overt message space stops being enforced',
    file: 'src/anamorphic.ts',
    from: '  if (!declared || declared.label !== choice.label || declared.scalar !== choice.scalar) {',
    to: '  if (false) {',
    suite: 'src/anamorphic.test.ts',
    test: 'rejects malformed double-key inputs and undeclared covert messages'
  },
  {
    name: 'the double-key table is built over the overt space instead of the covert one',
    file: 'src/anamorphic.ts',
    from: '  for (const message of COVERT_MESSAGES) {',
    to: '  for (const message of OVERT_MESSAGES) {',
    suite: 'src/anamorphic.test.ts',
    test: 'builds one injective lookup entry for every bounded covert symbol'
  },
  {
    name: 'the wire-shape check degenerates into a claim that cannot fail',
    file: 'src/anamorphic.ts',
    from: "  if (Object.keys(ciphertext).sort().join(',') !== 'c1,c2') return false;",
    to: '  return true;',
    suite: 'src/anamorphic.test.ts',
    test: 'the wire-shape check is falsifiable'
  },
  {
    name: 'the RNG byte-count check is dropped from the scalar sampler',
    file: 'src/anamorphic.ts',
    from: "    if (bytes.length !== 32) throw new RangeError('RNG must return exactly 32 bytes');",
    to: '    void bytes;',
    suite: 'src/anamorphic.test.ts',
    test: 'rejects an RNG with the wrong byte count'
  },
  {
    name: 'the independent-double-key control is allowed to be vacuous',
    file: 'src/scenario.ts',
    from: '  if (doubleKeyFingerprint(wrongKey) === doubleKeyFingerprint(doubleKey)) {',
    to: '  if (false) {',
    suite: 'src/scenario.test.ts',
    test: 'refuses to render a vacuous independent-key control'
  },
  {
    name: 'comparison grants anamorphic security to the subliminal channel',
    file: 'src/comparison.ts',
    from: "    boundary: 'Not encryption and not anamorphic security',",
    to: "    boundary: 'Anamorphic encryption security',",
    suite: 'src/comparison.test.ts',
    test: 'keeps the anamorphic, subliminal, and decoy-container claims distinct'
  }
];

const touched = [...new Set(mutations.map((mutation) => join(root, mutation.file)))];
const originals = new Map(touched.map((file) => [file, readFileSync(file)]));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(command, args) {
  return spawnSync(command, args, { cwd: root, encoding: 'utf8', stdio: 'pipe' });
}

function restoreAll() {
  for (const [file, bytes] of originals) writeFileSync(file, bytes);
}

function assertRestored() {
  for (const [file, bytes] of originals) {
    if (digest(readFileSync(file)) !== digest(bytes)) {
      throw new Error(`${relative(root, file)} was not restored byte for byte`);
    }
  }
}

function treeDigest(directory) {
  const hash = createHash('sha256');
  const visit = (path) => {
    const entries = readdirSync(path, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const file = join(path, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile()) {
        hash.update(relative(directory, file));
        hash.update(readFileSync(file));
      } else throw new Error(`unsupported build artifact: ${relative(directory, file)}`);
    }
  };
  visit(directory);
  return hash.digest('hex');
}

function requireSuccess(result, message) {
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(message);
  }
}

let caught = 0;
try {
  const baseline = run(vitest, ['run']);
  requireSuccess(baseline, 'baseline: unmutated copy FAILED; mutation results would be meaningless');
  const baselineBuild = run(npm, ['run', 'build']);
  requireSuccess(baselineBuild, 'baseline build FAILED; mutation bundle checks would be meaningless');
  const cleanBundle = treeDigest(join(root, 'dist'));
  console.log('baseline: unmutated copy PASSES');

  for (const mutation of mutations) {
    const file = join(root, mutation.file);
    const originalText = originals.get(file).toString('utf8');
    const occurrences = originalText.split(mutation.from).length - 1;
    if (occurrences !== 1) {
      throw new Error(`${mutation.name}: expected one source anchor, found ${occurrences}`);
    }
    writeFileSync(file, originalText.replace(mutation.from, mutation.to));

    const result = run(vitest, ['run', mutation.suite, '-t', mutation.test]);
    if (result.status === 0) {
      process.stderr.write(result.stdout ?? '');
      process.stderr.write(result.stderr ?? '');
      throw new Error(`SURVIVED: ${mutation.name}`);
    }
    const build = run(npm, ['run', 'build']);
    requireSuccess(build, `mutated build failed instead of producing testable output: ${mutation.name}`);
    if (treeDigest(join(root, 'dist')) === cleanBundle) {
      throw new Error(`mutation did not reach the production bundle: ${mutation.name}`);
    }
    writeFileSync(file, originals.get(file));
    caught += 1;
    console.log(`caught ${caught}/${mutations.length}: ${mutation.name}`);
  }

  assertRestored();
  const finalBaseline = run(vitest, ['run']);
  requireSuccess(finalBaseline, 'restored source does not pass its clean baseline');
  const finalBuild = run(npm, ['run', 'build']);
  requireSuccess(finalBuild, 'restored source does not build');
  if (treeDigest(join(root, 'dist')) !== cleanBundle) {
    throw new Error('restored production bundle differs from the clean baseline');
  }
  console.log(`all ${caught} mutation(s) caught; sources and production bundle restored byte for byte`);
} finally {
  restoreAll();
  assertRestored();
}

