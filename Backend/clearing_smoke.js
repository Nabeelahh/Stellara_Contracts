// Minimal smoke runner simulating CCP flows without project deps
// Run: node clearing_smoke.js

function simpleClearing() {
  const positions = new Map();
  const margins = new Map();
  const defaultFund = { total: 0, contributions: new Map() };

  function ensureAccount(memberId) {
    if (!margins.has(memberId)) margins.set(memberId, { initial: 0, variation: 0, balance: 0 });
  }

  function calculateInitialMargin(quantity, price) {
    return Math.abs(quantity * price) * 0.05;
  }

  function acceptTrade(trade) {
    const buyId = trade.tradeId + ':buy';
    const sellId = trade.tradeId + ':sell';
    const buyerPos = { positionId: buyId, memberId: trade.buyerId, instrument: trade.instrument, quantity: trade.notional, avgPrice: trade.price, unrealizedPnl: 0 };
    const sellerPos = { positionId: sellId, memberId: trade.sellerId, instrument: trade.instrument, quantity: -trade.notional, avgPrice: trade.price, unrealizedPnl: 0 };
    positions.set(buyId, buyerPos);
    positions.set(sellId, sellerPos);

    ensureAccount(trade.buyerId);
    ensureAccount(trade.sellerId);

    const imBuyer = calculateInitialMargin(buyerPos.quantity, buyerPos.avgPrice);
    const imSeller = calculateInitialMargin(Math.abs(sellerPos.quantity), sellerPos.avgPrice);

    const bAcct = margins.get(trade.buyerId);
    bAcct.initial += imBuyer; bAcct.balance -= imBuyer;
    const sAcct = margins.get(trade.sellerId);
    sAcct.initial += imSeller; sAcct.balance -= imSeller;

    return { buyId, sellId, imBuyer, imSeller };
  }

  function contributeDefault(memberId, amount) {
    ensureAccount(memberId);
    const prev = defaultFund.contributions.get(memberId) || 0;
    defaultFund.contributions.set(memberId, prev + amount);
    defaultFund.total += amount;
    const acct = margins.get(memberId);
    acct.balance -= amount;
    return true;
  }

  function settle(instrument, marketPrice) {
    let totalVariation = 0;
    const details = [];
    for (const pos of positions.values()) {
      if (pos.instrument !== instrument) continue;
      const old = pos.unrealizedPnl || 0;
      const newPnl = pos.quantity * (marketPrice - pos.avgPrice);
      const variation = newPnl - old;
      pos.unrealizedPnl = newPnl;
      const acct = margins.get(pos.memberId);
      acct.variation += variation; acct.balance -= variation;
      // default check
      let drained = 0;
      if (acct.balance < -acct.initial) {
        // drain from default fund
        const need = Math.abs(acct.balance) - acct.initial;
        const drain = Math.min(defaultFund.total, need);
        defaultFund.total -= drain; drained = drain;
        acct.balance += drain; // cover shortfall
      }
      details.push({ memberId: pos.memberId, variation, drainedDefaultFund: drained });
      totalVariation += variation;
    }
    return { instrument, totalVariation, details };
  }

  return { acceptTrade, contributeDefault, settle, margins, positions, defaultFund };
}

// Run simulation
const ccp = simpleClearing();
console.log('=== Accept trade ===');
const trade = { tradeId: 't100', buyerId: 'M1', sellerId: 'M2', instrument: 'BTC-USD-FUT', notional: 5, price: 20000 };
console.log(ccp.acceptTrade(trade));

console.log('=== Contribute default fund ===');
ccp.contributeDefault('M1', 1000);
ccp.contributeDefault('M2', 500);
console.log('Default fund total:', ccp.defaultFund.total);

console.log('=== Settle MTM at price 21000 ===');
const res = ccp.settle('BTC-USD-FUT', 21000);
console.log('Settlement result:', res);

console.log('=== Member margins ===');
console.log(Array.from(ccp.margins.entries()));

console.log('Smoke test completed successfully');
