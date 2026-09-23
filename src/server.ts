import Fastify from 'fastify';
import { z } from 'zod';

const app = Fastify({ logger: true });

const analysisRequest = z.object({
  input: z.object({ type: z.enum(['url', 'text']), value: z.string().min(1).max(20_000) }),
  context: z.object({ source: z.enum(['paste', 'share', 'screenshot']).optional(), locale: z.string().optional() }).optional(),
});

const trustedDomains: Record<string, { organisation: string; officialDomain: string }> = {
  'frsc.gov.ng': { organisation: 'Federal Road Safety Corps', officialDomain: 'frsc.gov.ng' },
};

function analyse(value: string) {
  const urls = [...value.matchAll(/https?:\/\/[^\s]+|\b[a-z0-9-]+\.[a-z]{2,}(?:\/[^\s]*)?/gi)].map((match) => match[0]);
  const evidence: Array<{ kind: string; severity: 'high' | 'medium'; title: string; detail: string }> = [];
  const lower = value.toLowerCase();
  if (lower.includes('frscgov.top')) evidence.push({ kind: 'official_domain_mismatch', severity: 'high', title: 'This is not FRSC’s official domain', detail: 'The message uses frscgov.top. FRSC’s verified domain is frsc.gov.ng.' });
  if (/urgent|immediately|action required|offence|penalty|suspend/i.test(value)) evidence.push({ kind: 'urgency', severity: 'medium', title: 'The message uses pressure to rush you', detail: 'Unexpected urgent requests should be verified through an official channel.' });
  const risk = evidence.some((item) => item.severity === 'high') ? 'high' : evidence.length ? 'caution' : 'unknown';
  return { analysisId: crypto.randomUUID(), risk: { level: risk, summary: risk === 'high' ? 'Likely organisation impersonation.' : risk === 'caution' ? 'This needs independent verification.' : 'No known warning found.' }, urls, evidence, safeActions: evidence.some((item) => item.kind === 'official_domain_mismatch') ? [{ type: 'open_verified_site', label: 'Visit the official FRSC website', url: 'https://frsc.gov.ng' }] : [] };
}

app.get('/health', async () => ({ status: 'ok' }));
app.post('/v1/analyses', async (request, reply) => {
  const parsed = analysisRequest.safeParse(request.body);
  if (!parsed.success) return reply.status(400).send({ error: 'Invalid analysis request.' });
  return analyse(parsed.data.input.value);
});

await app.listen({ host: '127.0.0.1', port: 3000 });
