import type { Analysis, Evidence } from './analyse.js';
import type { AppConfig } from './config.js';

type NoulAnswer = { type: 'noul'; noul: number };
type ChoiceAnswer = { type: 'choice'; choice: string; confidence: number };
type SystemOneResponse = { answers: Record<string, NoulAnswer | ChoiceAnswer> };

export type DecisionSignals = {
  urgency: number;
  impersonation: number;
  requestedHarm: string;
  harmConfidence: number;
};

export interface DecisionProvider {
  evaluate(text: string): Promise<DecisionSignals | undefined>;
}

export function redactSensitiveText(value: string): string {
  return value
    .replace(/\b\d{6}\b/g, '[REDACTED_CODE]')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[REDACTED_CARD]');
}

export class TypeSafeDecisionProvider implements DecisionProvider {
  constructor(private readonly apiKey: string, private readonly model: string) {}

  async evaluate(text: string): Promise<DecisionSignals | undefined> {
    try {
      const response = await fetch('https://api.typesafe.ai/v1/systemone', {
        method: 'POST',
        headers: { authorization: `Bearer ${this.apiKey}`, 'content-type': 'application/json' },
        signal: AbortSignal.timeout(4_500),
        body: JSON.stringify({
          model: this.model,
          state: redactSensitiveText(text),
          questions: {
            urgency: {
              type: 'noul',
              instructions: 'Does this message pressure the recipient to act quickly through a deadline, threat, or urgent demand?',
            },
            impersonation: {
              type: 'noul',
              instructions: 'Does this message claim or strongly imply it is from an organisation, government body, bank, delivery provider, telecom, or payment service?',
            },
            requested_harm: {
              type: 'choice',
              instructions: 'What is the most concerning action the message asks the recipient to take?',
              criteria: {
                none: 'No concerning action is requested.',
                credential_or_code: 'It asks for a password, PIN, OTP, verification code, card, banking, or identity information.',
                payment: 'It asks for money, a transfer, a fee, or payment details.',
                install_or_download: 'It asks the recipient to install an app or download a file.',
              },
            },
          },
        }),
      });
      if (!response.ok) return undefined;
      const body = await response.json() as SystemOneResponse;
      const urgency = body.answers.urgency;
      const impersonation = body.answers.impersonation;
      const requestedHarm = body.answers.requested_harm;
      if (urgency?.type !== 'noul' || impersonation?.type !== 'noul' || requestedHarm?.type !== 'choice') return undefined;
      return {
        urgency: urgency.noul,
        impersonation: impersonation.noul,
        requestedHarm: requestedHarm.choice,
        harmConfidence: requestedHarm.confidence,
      };
    } catch {
      return undefined;
    }
  }
}

export function createDecisionProvider(config: AppConfig): DecisionProvider | undefined {
  return config.TYPESAFE_API_KEY ? new TypeSafeDecisionProvider(config.TYPESAFE_API_KEY, config.TYPESAFE_MODEL) : undefined;
}

export async function enrichWithDecisioning(
  analysis: Analysis,
  text: string,
  provider: DecisionProvider | undefined,
): Promise<Analysis> {
  if (!provider) return analysis;
  const signals = await provider.evaluate(text);
  if (!signals) return analysis;

  const evidence: Evidence[] = [];
  let score = analysis.risk.score;
  if (signals.urgency >= 0.8 && !analysis.evidence.some((item) => item.kind === 'urgency')) {
    evidence.push({ kind: 'model_urgency', severity: 'medium', title: 'The message appears designed to rush you', detail: 'Pause detected time pressure or a threat. Verify independently before acting.' });
    score += 15;
  }
  if (signals.impersonation >= 0.85) {
    evidence.push({ kind: 'model_impersonation_claim', severity: 'low', title: 'The message appears to claim institutional authority', detail: 'A claim of authority is not proof of identity. Use a verified contact route instead of the message link.' });
    score += 10;
  }
  if (signals.harmConfidence >= 0.8 && signals.requestedHarm !== 'none') {
    evidence.push({ kind: 'model_requested_harm', severity: 'medium', title: 'The message may be requesting a sensitive action', detail: 'Do not share codes, credentials, payment details, or install software from an unexpected request.' });
    score += 20;
  }
  if (evidence.length === 0) return analysis;
  const level = analysis.risk.level === 'high' || score >= 60 ? 'high' : score >= 30 ? 'caution' : analysis.risk.level;
  return {
    ...analysis,
    evidence: [...analysis.evidence, ...evidence],
    risk: level === analysis.risk.level ? { ...analysis.risk, score } : {
      level,
      score,
      summary: level === 'high' ? 'Likely scam or organisation impersonation.' : 'This needs independent verification.',
      guidance: level === 'high'
        ? 'Do not open the link, pay, or share any codes. Verify independently using an official channel.'
        : 'Do not act through this message. Verify the request through an official channel you find yourself.',
    },
  };
}
