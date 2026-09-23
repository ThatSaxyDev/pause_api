import assert from 'node:assert/strict';
import test from 'node:test';

import { analyseInput } from './analyse.js';
import { enrichWithReputation, type ReputationProvider } from './reputation.js';
import { enrichWithDecisioning, redactSensitiveText, type DecisionProvider } from './decisioning.js';

test('flags the FRSC lookalike domain as high risk', () => {
  const result = analyseInput('FRSC traffic offence: act immediately at https://frscgov.top/ng', 'test-frsc');
  assert.equal(result.risk.level, 'high');
  assert.equal(result.risk.score, 75);
  assert.match(result.evidence[0]!.detail, /frscgov\.top/);
  assert.deepEqual(result.safeActions[0]?.url, 'https://frsc.gov.ng');
});

test('does not call an ordinary official FRSC address a mismatch', () => {
  const result = analyseInput('Please confirm at https://frsc.gov.ng', 'test-official');
  assert.equal(result.risk.level, 'no_known_warning_found');
  assert.equal(result.evidence.length, 0);
});

test('flags hidden credentials and sensitive requests', () => {
  const result = analyseInput('Send your OTP now: https://frsc.gov.ng@evil.example/login', 'test-credentials');
  assert.equal(result.risk.level, 'high');
  assert.ok(result.evidence.some((item) => item.kind === 'embedded_credentials'));
  assert.ok(result.evidence.some((item) => item.kind === 'sensitive_data_request'));
});

test('flags generic payment-phishing signals without a registry match', () => {
  const result = analyseInput(
    'Final warning: verify your account and pay now at https://acme-payment.top/login',
    'test-generic',
  );
  assert.equal(result.risk.level, 'high');
  assert.ok(result.evidence.some((item) => item.kind === 'deceptive_host_shape'));
  assert.ok(result.evidence.some((item) => item.kind === 'sensitive_data_request'));
  assert.equal(result.safeActions.length, 0);
});

test('identifies hidden Unicode characters and applies rules after normalization', () => {
  const result = analyseInput(
    'Your business fun\u200Bding offer is approved. Pay\u200Bment now at https://secure-funding-portal.top/login',
    'test-hidden-unicode',
  );
  assert.equal(result.risk.level, 'high');
  assert.ok(result.evidence.some((item) => item.kind === 'hidden_unicode_characters'));
  assert.match(
    result.evidence.find((item) => item.kind === 'hidden_unicode_characters')!.detail,
    /hidden spacing character between “fun” and “ding” \(U\+200B\)/,
  );
  assert.ok(result.evidence.some((item) => item.kind === 'sensitive_data_request'));
});

test('makes a known-malicious reputation match high risk for any domain', async () => {
  const provider: ReputationProvider = {
    lookup: async () => ({ provider: 'google_web_risk', threatTypes: ['SOCIAL_ENGINEERING'] }),
  };
  const result = await enrichWithReputation(
    analyseInput('See https://unknown.example/path', 'test-reputation'),
    provider,
  );
  assert.equal(result.risk.level, 'high');
  assert.equal(result.risk.score, 100);
  assert.ok(result.evidence.some((item) => item.kind === 'known_malicious_reputation'));
});

test('redacts codes and treats decisioning as additive evidence', async () => {
  assert.doesNotMatch(redactSensitiveText('Your code is 123456'), /123456/);
  const provider: DecisionProvider = {
    evaluate: async () => ({ urgency: 0.95, impersonation: 0.9, requestedHarm: 'credential_or_code', harmConfidence: 0.95 }),
  };
  const result = await enrichWithDecisioning(
    analyseInput('Please see https://ordinary.example', 'test-decisioning'),
    'Please send 123456 now',
    provider,
  );
  assert.equal(result.risk.level, 'caution');
  assert.ok(result.evidence.some((item) => item.kind === 'model_requested_harm'));
});
