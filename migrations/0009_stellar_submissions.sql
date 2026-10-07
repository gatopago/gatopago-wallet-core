-- Stellar calls Wallet Core sent for members, by the nonce of their signed authorization. The app
-- asks after an answer it lost (closed tab, timeout): the network forgets a nonce once its signature
-- expires, this does not, so a sent payment is never paid again.
CREATE TABLE stellar_submissions (
  member_address TEXT NOT NULL REFERENCES members (address),
  nonce TEXT NOT NULL,
  transaction_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_address, nonce)
) STRICT;

CREATE INDEX stellar_submissions_created ON stellar_submissions (created_at);
