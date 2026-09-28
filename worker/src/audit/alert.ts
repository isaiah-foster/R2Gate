// Optional webhook (PLAN §5.6, ALERT_WEBHOOK_URL): one POST per audit that found something. It
// carries counts and log indexes, never object keys: the receiver may be a chat service, and the
// findings themselves are in the log and behind /api/v1/findings.

import { ConfigError } from '../config.ts';

export interface AlertSummary {
  readonly type: 'r2notary.audit';
  readonly origin: string;
  readonly scanId: string;
  readonly objectsScanned: number;
  readonly findings: number;
  readonly startIndex: number | null;
  readonly endIndex: number | null;
  readonly reportKey: string | null;
}

export const ALERT_TIMEOUT_MS = 10_000;

/** Parses the optional ALERT_WEBHOOK_URL secret. Only https: the payload describes the bucket. */
export function parseWebhookUrl(value: string | undefined): URL | null {
  if (value === undefined || value === '') return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError('ALERT_WEBHOOK_URL is not a URL');
  }
  if (url.protocol !== 'https:') throw new ConfigError('ALERT_WEBHOOK_URL must be https');
  return url;
}

export class AlertError extends Error {
  override name = 'AlertError';
}

/** POSTs the summary as JSON. Throws on a network error, a timeout or a non-2xx answer. */
export async function sendAlert(
  url: URL,
  summary: AlertSummary,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  const res = await fetcher(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(summary),
    signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
  });
  await res.body?.cancel();
  if (!res.ok) throw new AlertError(`webhook answered ${String(res.status)}`);
}
