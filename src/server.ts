import 'dotenv/config';

import { buildApp } from './app.js';
import { readConfig } from './config.js';

const config = readConfig();
const app = await buildApp(config);

await app.listen({ host: config.HOST, port: config.PORT });

async function shutdown(signal: string) {
  app.log.info({ signal }, 'Shutting down');
  await app.close();
  process.exit(0);
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));
