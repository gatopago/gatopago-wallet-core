-- A link to the member's social profile, shown on their public payment page.
ALTER TABLE members ADD COLUMN social_url TEXT;

-- Early-access survey for a future GatoPago Card. Not an application for a card.
CREATE TABLE card_interest (
  member_id TEXT PRIMARY KEY REFERENCES members (id),
  country TEXT NOT NULL,
  use_case TEXT NOT NULL,
  monthly_spend TEXT NOT NULL,
  card_preference TEXT NOT NULL,
  wallet_pay TEXT NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
