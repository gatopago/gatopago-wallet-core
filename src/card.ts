import type { Config } from './config';
import { HttpError, json, readJson } from './http';
import { signedInMember } from './profile';

/** The early-access survey for a future GatoPago Card, and the answers each question accepts. */
const QUESTIONS = {
  use_case: ['subscriptions', 'online', 'travel', 'advertising', 'daily', 'other'],
  monthly_spend: ['under-100', '100-500', '500-1000', 'over-1000', 'prefer-not'],
  card_preference: ['virtual', 'physical', 'both'],
  wallet_pay: ['essential', 'important', 'not-important'],
} as const;

type Interest = { country: string } & {
  [question in keyof typeof QUESTIONS]: (typeof QUESTIONS)[question][number];
};

/** `GET /app/v1/card-interest`: the member's answers, or `null` before answering. */
export async function readCardInterest(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const interest = await env.WALLET_DB.prepare(
    `SELECT country, use_case, monthly_spend, card_preference, wallet_pay, updated_at
     FROM card_interest WHERE member_id = ?`,
  )
    .bind(member.id)
    .first();
  return json({ interest });
}

/** `PUT /app/v1/card-interest`: saves or replaces the member's answers. */
export async function saveCardInterest(
  request: Request,
  env: Env,
  config: Config,
): Promise<Response> {
  const member = await signedInMember(request, env, config);
  const body = await readJson<Partial<Record<keyof Interest, unknown>>>(request);
  const country = typeof body.country === 'string' ? body.country.trim() : '';
  if (country.length < 2 || country.length > 80) throw new HttpError(400, 'INVALID_COUNTRY');
  for (const [question, answers] of Object.entries(QUESTIONS))
    if (!(answers as readonly unknown[]).includes(body[question as keyof typeof QUESTIONS]))
      throw new HttpError(400, 'INVALID_ANSWER');
  const interest = { ...(body as Interest), country };
  const updatedAt = Math.floor(Date.now() / 1000);
  await env.WALLET_DB.prepare(
    `INSERT INTO card_interest (member_id, country, use_case, monthly_spend, card_preference, wallet_pay, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (member_id) DO UPDATE SET country = excluded.country, use_case = excluded.use_case,
       monthly_spend = excluded.monthly_spend, card_preference = excluded.card_preference,
       wallet_pay = excluded.wallet_pay, updated_at = excluded.updated_at`,
  )
    .bind(
      member.id,
      interest.country,
      interest.use_case,
      interest.monthly_spend,
      interest.card_preference,
      interest.wallet_pay,
      updatedAt,
    )
    .run();
  return json({
    interest: {
      country: interest.country,
      use_case: interest.use_case,
      monthly_spend: interest.monthly_spend,
      card_preference: interest.card_preference,
      wallet_pay: interest.wallet_pay,
      updated_at: updatedAt,
    },
  });
}
