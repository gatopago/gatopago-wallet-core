import {
  encodeAbiParameters,
  encodeEventTopics,
  erc20Abi,
  toHex,
  zeroHash,
  type Address,
  type Hex,
} from 'viem';
import { aavePoolAbi, loadAaveMarket, marketToken } from '@gatopago/shared/v3/aave-market';
import { readMoneyReview, writeMoneyReview } from '@gatopago/shared/v3/money-review-record';
import type { MoneyKind } from '@gatopago/shared/v3/money-wire';
import { operationReceiptAbi } from '../src/execution/userOperationReceipt';
import { verifyMoneyReceipt } from '../src/money/moneyReceipt';
import { createMoneyFixture } from './money.fixture';

export async function createMoneyReceiptFixture(kind: MoneyKind, success = true) {
  const f = createMoneyFixture(kind),
    signed = writeMoneyReview({
      ...f.review,
      approved_at: f.now,
      proofs: [
        { signerIndex: 0, kind: 'webauthn', assertion: f.keys.assertion(f.candidate.digest) },
      ],
    });
  const record = await readMoneyReview(signed.json, signed.digest),
    c = record.candidate,
    market = loadAaveMarket(record.review.context.market);
  const token = marketToken(market),
    tx = f.hash,
    block = `0x${'22'.repeat(32)}` as Hex;
  const base = {
    transactionHash: tx,
    blockHash: block,
    blockNumber: '0x7c',
    transactionIndex: '0x0',
    removed: false,
  };
  const topic = (a: Address) => encodeAbiParameters([{ type: 'address' }], [a]);
  const amount = (n: bigint) => encodeAbiParameters([{ type: 'uint256' }], [n]);
  const log = (address: Address, first: Hex, data: Hex, extra: Hex[] = []) => ({
    ...base,
    address,
    topics: [first, ...extra],
    data,
    logIndex: '0x0',
  });
  const event = (name: (typeof operationReceiptAbi)[number]['name']) =>
    encodeEventTopics({ abi: operationReceiptAbi, eventName: name })[0];
  const transfer = (from: Address, to: Address) =>
    log(
      token,
      encodeEventTopics({ abi: erc20Abi, eventName: 'Transfer' })[0],
      amount(BigInt(c.request.amount_atomic)),
      [topic(from), topic(to)],
    );
  const approval = (n: bigint) =>
    log(token, encodeEventTopics({ abi: erc20Abi, eventName: 'Approval' })[0], amount(n), [
      topic(c.account),
      topic(market.pool),
    ]);
  const logs = [log(c.plan.entryPoint, event('BeforeExecution'), '0x')];
  if (success) {
    if (kind === 'aave_supply')
      logs.push(
        approval(0n),
        approval(BigInt(c.request.amount_atomic)),
        transfer(c.account, market.a_token),
        log(
          market.pool,
          encodeEventTopics({ abi: aavePoolAbi, eventName: 'Supply' })[0],
          encodeAbiParameters(
            [{ type: 'address' }, { type: 'uint256' }],
            [c.account, BigInt(c.request.amount_atomic)],
          ),
          [topic(token), topic(c.account), encodeAbiParameters([{ type: 'uint16' }], [0])],
        ),
        approval(0n),
      );
    else {
      logs.push(
        transfer(market.a_token, c.account),
        log(
          market.pool,
          encodeEventTopics({ abi: aavePoolAbi, eventName: 'Withdraw' })[0],
          amount(BigInt(c.request.amount_atomic)),
          [topic(token), topic(c.account), topic(c.account)],
        ),
      );
      if (kind === 'aave_withdraw_and_pay')
        logs.push(transfer(c.account, c.request.recipient_address!));
    }
    logs.push(
      log(
        c.account,
        event('CallsExecuted'),
        encodeAbiParameters([{ type: 'uint64' }, { type: 'uint8' }], [c.plan.securityVersion, 0]),
        [c.plan.callsHash],
      ),
    );
  }
  const operation = log(
    c.plan.entryPoint,
    event('UserOperationEvent'),
    encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'bool' }, { type: 'uint256' }, { type: 'uint256' }],
      [c.plan.nonce, success, 100n, 50n],
    ),
    [c.userOpHash, topic(c.account), zeroHash],
  );
  logs.push(operation);
  const reindex = () =>
    logs.forEach((l, i) => {
      l.logIndex = toHex(i);
    });
  reindex();
  const receipt = { ...base, status: '0x1', logs };
  return {
    f,
    record,
    receipt,
    logs,
    token,
    market,
    topic,
    amount,
    transfer,
    approval,
    operation,
    reindex,
    run: () => verifyMoneyReceipt(record, tx, receipt),
  };
}
