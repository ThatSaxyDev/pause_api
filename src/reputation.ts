import type { Analysis, Evidence } from './analyse.js';
import type { AppConfig } from './config.js';

export type ReputationMatch = {
  provider: 'google_web_risk';
  threatTypes: string[];
};

export interface ReputationProvider {
  lookup(url: string): Promise<ReputationMatch | undefined>;
}

export class GoogleWebRiskProvider implements ReputationProvider {
  private readonly cache = new Map<string, { expiresAt: number; value: ReputationMatch | undefined }>();

  constructor(private readonly apiKey: string) {}

  async lookup(uri: string): Promise<ReputationMatch | undefined> {
    const cached = this.cache.get(uri);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    const requestUrl = new URL('https://webrisk.googleapis.com/v1/uris:search');
    requestUrl.searchParams.set('key', this.apiKey);
    requestUrl.searchParams.set('uri', uri);
    requestUrl.searchParams.append('threatTypes', 'MALWARE');
    requestUrl.searchParams.append('threatTypes', 'SOCIAL_ENGINEERING');
    requestUrl.searchParams.append('threatTypes', 'UNWANTED_SOFTWARE');

    try {
      const response = await fetch(requestUrl, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(3_500),
      });
      if (!response.ok) return undefined;
      const body = await response.json() as { threat?: { threatTypes?: string[]; expireTime?: string } };
      const value = body.threat?.threatTypes?.length
        ? { provider: 'google_web_risk' as const, threatTypes: body.threat.threatTypes }
        : undefined;
      const expiry = body.threat?.expireTime ? Date.parse(body.threat.expireTime) : NaN;
      this.cache.set(uri, { value, expiresAt: Number.isNaN(expiry) ? Date.now() + 300_000 : expiry });
      return value;
    } catch {
      // Reputation providers are enrichment. A timeout must never turn an
      // unknown URL into a safe verdict or make core analysis unavailable.
      return undefined;
    }
  }
}

export function createReputationProvider(config: AppConfig): ReputationProvider | undefined {
  return config.WEB_RISK_API_KEY ? new GoogleWebRiskProvider(config.WEB_RISK_API_KEY) : undefined;
}

export async function enrichWithReputation(
  analysis: Analysis,
  provider: ReputationProvider | undefined,
): Promise<Analysis> {
  if (!provider) return analysis;
  const matches = await Promise.all(
    analysis.urls.map(async ({ original }) => ({ original, match: await provider.lookup(original) })),
  );
  const matched = matches.find((item) => item.match);
  if (!matched?.match) return analysis;

  const evidence: Evidence = {
    kind: 'known_malicious_reputation',
    severity: 'high',
    title: 'This link is listed as unsafe',
    detail: 'A threat-intelligence provider identified this address as associated with phishing, malware, or unwanted software.',
  };
  return {
    ...analysis,
    evidence: [...analysis.evidence, evidence],
    risk: {
      level: 'high',
      score: Math.max(100, analysis.risk.score),
      summary: 'This link is listed as unsafe.',
      guidance: 'Do not open the link, download anything, pay, or share any codes. Verify through an official channel you find yourself.',
    },
  };
}
