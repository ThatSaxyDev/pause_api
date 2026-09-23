import assert from 'node:assert/strict';
import test from 'node:test';

import { buildApp } from './app.js';
import { readConfig } from './config.js';

const config = readConfig({ NODE_ENV: 'test', RATE_LIMIT_MAX: '1000' });

test('exposes liveness and readiness checks', async () => {
  const app = await buildApp(config);
  const live = await app.inject({ method: 'GET', url: '/health/live' });
  const ready = await app.inject({ method: 'GET', url: '/health/ready' });
  assert.equal(live.statusCode, 200);
  assert.equal(ready.statusCode, 200);
  assert.equal(ready.json().status, 'ready');
  await app.close();
});

test('validates requests without returning submitted content', async () => {
  const app = await buildApp(config);
  const response = await app.inject({
    method: 'POST',
    url: '/v1/analyses',
    payload: { input: { type: 'text', value: '' } },
  });
  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, 'INVALID_REQUEST');
  assert.doesNotMatch(response.body, /input/i);
  await app.close();
});

test('returns a stable analysis response contract', async () => {
  const app = await buildApp(config);
  const response = await app.inject({
    method: 'POST',
    url: '/v1/analyses',
    payload: { input: { type: 'url', value: 'https://frscgov.top/ng' } },
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.risk.level, 'high');
  assert.equal(body.policyVersion, '2026-09-mvp.2');
  assert.equal(body.safeActions[0].url, 'https://frsc.gov.ng');
  await app.close();
});
