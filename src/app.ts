import crypto from 'node:crypto';

import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import { z } from 'zod';

import { analyseInput } from './analyse.js';
import type { AppConfig } from './config.js';
import { createDecisionProvider, enrichWithDecisioning } from './decisioning.js';
import { createReputationProvider, enrichWithReputation } from './reputation.js';

const analysisRequest = z.object({
  input: z.object({
    type: z.enum(['url', 'text']),
    value: z.string().trim().min(1).max(20_000),
  }),
  context: z.object({
    source: z.enum(['paste', 'share', 'screenshot']).default('paste'),
    locale: z.string().trim().min(2).max(16).optional(),
  }).optional(),
});

export async function buildApp(config: AppConfig) {
  const reputationProvider = createReputationProvider(config);
  const decisionProvider = createDecisionProvider(config);
  const app = Fastify({
    logger: { level: config.NODE_ENV === 'test' ? 'silent' : 'info' },
    bodyLimit: 25_000,
    genReqId: () => crypto.randomUUID(),
  });

  await app.register(helmet, { contentSecurityPolicy: false, crossOriginResourcePolicy: false });
  await app.register(cors, { origin: config.CORS_ORIGIN ? config.CORS_ORIGIN.split(',') : false });
  await app.register(rateLimit, {
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_WINDOW_MS,
    errorResponseBuilder: () => ({ error: { code: 'RATE_LIMITED', message: 'Too many requests. Please try again shortly.' } }),
  });

  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async () => ({ status: 'ready', version: '0.1.0' }));
  // Kept for simple hosting checks during the MVP.
  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/v1/analyses', async (request, reply) => {
    const parsed = analysisRequest.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: { code: 'INVALID_REQUEST', message: 'Provide a link or message of up to 20,000 characters.' },
      });
    }
    // Do not log or persist submitted messages/URLs in the MVP.
    const baseline = analyseInput(parsed.data.input.value);
    const reputationEnriched = await enrichWithReputation(baseline, reputationProvider);
    return enrichWithDecisioning(reputationEnriched, parsed.data.input.value, decisionProvider);
  });

  app.setErrorHandler((error, _request, reply) => {
    if ((error as { statusCode?: number }).statusCode === 413) {
      return reply.status(413).send({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'The submitted content is too large.' } });
    }
    app.log.error({ err: error }, 'Unhandled request error');
    return reply.status(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Pause could not analyse this item right now.' } });
  });

  return app;
}
