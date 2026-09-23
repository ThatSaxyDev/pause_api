import { z } from 'zod';

const optionalSecret = z.preprocess(
  (value) => value === '' ? undefined : value,
  z.string().min(1).optional(),
);

const environment = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  CORS_ORIGIN: z.string().optional(),
  WEB_RISK_API_KEY: optionalSecret,
  TYPESAFE_API_KEY: optionalSecret,
  TYPESAFE_MODEL: z.string().min(1).default('jev-latest'),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(1_000).default(60),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1_000).max(3_600_000).default(60_000),
});

export type AppConfig = z.infer<typeof environment>;

export function readConfig(input: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = environment.safeParse(input);
  if (!parsed.success) {
    throw new Error(`Invalid environment configuration: ${parsed.error.issues[0]?.message}`);
  }
  return parsed.data;
}
