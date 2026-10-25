import * as core from '@actions/core';
import { run } from './lifecycle';

run(core).catch(() => core.setFailed('Token exchange failed. Check id-token: write, broker-url and broker authorization logs.'));
