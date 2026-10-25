const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, readFileSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

test('packaged action runs without node_modules and reports a safe exchange error', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'broker-action-'));
  try {
    const main = path.join(dir,'main.cjs');
    writeFileSync(main, readFileSync(path.join(__dirname,'../dist/main/index.js')));
    const result = spawnSync(process.execPath, [main], {encoding:'utf8', env:{PATH:process.env.PATH}});
    assert.equal(result.status,1,result.stderr);
    assert.match(result.stdout, /Token exchange failed/);
    assert.doesNotMatch(result.stdout+result.stderr,/Cannot find module|MODULE_NOT_FOUND/);
    const post = path.join(dir,'post.cjs');
    writeFileSync(post, readFileSync(path.join(__dirname,'../dist/post/index.js')));
    const cleanup = spawnSync(process.execPath, [post], {encoding:'utf8', env:{PATH:process.env.PATH}});
    assert.equal(cleanup.status,0,cleanup.stderr);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
