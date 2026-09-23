'use strict';

const {spawnSync} = require('node:child_process');

const tests = [
  'sam/olea/functions/verification/attestation-verifier.test.js',
  'sam/olea/functions/verification/verification-contract.test.js',
];
const result = spawnSync(process.execPath, ['--test', ...tests], {stdio: 'inherit', cwd: __dirname + '/..'});
process.exit(result.status === null ? 1 : result.status);
