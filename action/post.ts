import * as core from '@actions/core';
import { cleanup } from './lifecycle';

cleanup(core).catch(() => core.setFailed('Token revocation failed; the token remains valid until its expiration time.'));
