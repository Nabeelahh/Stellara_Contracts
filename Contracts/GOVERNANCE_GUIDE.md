# Stellara Upgrade Governance - User Guide

## Quick Start Guide

This guide provides step-by-step instructions for proposing, approving, and executing contract upgrades using the Stellara governance system.

## Prerequisites

- Stellar CLI installed and configured
- Funded testnet account(s)
- Identified governance participants (admin, approvers, executor)
- Understanding of contract addresses and symbols

## Part 1: Initial Setup

### Step 1: Deploy the Upgradeable Contract

```bash
# Build contract
cd Contracts/contracts/trading
cargo build --release --target wasm32-unknown-unknown

# Deploy contract
TRADING_ID=$(stellar contract deploy \
  --wasm ../../target/wasm32-unknown-unknown/release/trading.wasm \
  --source my-account \
  --network testnet)

echo "Trading Contract ID: $TRADING_ID"
```

### Step 2: Initialize with Governance Roles

```bash
# Define governance participants
ADMIN="GXXXXXX..."        # Your admin account
APPROVER_1="GXXXXXX..."   # First multi-sig signer
APPROVER_2="GXXXXXX..."   # Second multi-sig signer
APPROVER_3="GXXXXXX..."   # Third multi-sig signer
EXECUTOR="GXXXXXX..."     # Execution account

# Initialize contract with 3-of-3 multi-sig requirement
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- init \
  --admin "$ADMIN" \
  --approvers '["'"$APPROVER_1"'", "'"$APPROVER_2"'", "'"$APPROVER_3"'"]' \
  --executor "$EXECUTOR"
```

### Step 3: Verify Initialization

```bash
# Check contract version (should be 1)
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_version

# Check trading stats (should be empty)
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_stats
```

## Part 2: Proposing an Upgrade

### Step 4: Create Upgrade Proposal

```bash
# Define upgrade parameters
NEW_CONTRACT_HASH="QmUpgradeHashV2..."  # IPFS hash or contract address of V2
DESCRIPTION="Add fee tracking and governance controls"
APPROVAL_THRESHOLD=2                    # 2 of 3 approvals needed
TIMELOCK_DELAY=3600                     # 1 hour delay for testing
                                        # Use 86400 (24h) for mainnet

# Propose the upgrade (from ADMIN account)
PROPOSAL_ID=$(stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- propose_upgrade \
  --admin "$ADMIN" \
  --new_contract_hash "$NEW_CONTRACT_HASH" \
  --description "$DESCRIPTION" \
  --approvers '["'"$APPROVER_1"'", "'"$APPROVER_2"'", "'"$APPROVER_3"'"]' \
  --approval_threshold "$APPROVAL_THRESHOLD" \
  --timelock_delay "$TIMELOCK_DELAY" | grep -oP '\d+')

echo "Proposal ID: $PROPOSAL_ID"
```

### Step 5: Verify Proposal Creation

```bash
# Get proposal details
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected output:
# {
#   "id": 1,
#   "proposer": "GXXXXXX...",
#   "new_contract_hash": "QmUpgradeHashV2...",
#   "description": "Add fee tracking...",
#   "approval_threshold": 2,
#   "approvers": ["GXXXXXX...", "GXXXXXX...", "GXXXXXX..."],
#   "approvals_count": 0,
#   "status": "Pending",
#   "created_at": 1678886400,
#   "execution_time": 1678890000,
#   "executed": false
# }
```

## Part 3: Multi-Sig Approval

### Step 6: First Approver Votes

```bash
# APPROVER_1 approves the upgrade
stellar contract invoke \
  --id $TRADING_ID \
  --source $APPROVER_1 \
  --network testnet \
  -- approve_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --approver "$APPROVER_1"

echo "First approval submitted"

# Check proposal status
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected: approvals_count = 1, status = Pending
```

### Step 7: Second Approver Votes

```bash
# APPROVER_2 approves the upgrade
stellar contract invoke \
  --id $TRADING_ID \
  --source $APPROVER_2 \
  --network testnet \
  -- approve_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --approver "$APPROVER_2"

echo "Second approval submitted"

# Check proposal status
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected: approvals_count = 2, status = Approved ✓
```

### Step 8: Wait for Timelock Expiration

```bash
# Show current time
date +%s

# Calculate when upgrade can be executed
# execution_time from proposal (e.g., 1678890000)
# If current time < execution_time, wait or use testnet time advancement

# Option A: Wait for real time
echo "Waiting $TIMELOCK_DELAY seconds for timelock to expire..."
sleep $TIMELOCK_DELAY

# Option B: Use Soroban test utilities (in tests)
# env.ledger().set_timestamp(execution_time + 1);
```

## Part 4: Execution

### Step 9: Execute Upgrade

```bash
# After timelock expires, EXECUTOR can execute the upgrade
stellar contract invoke \
  --id $TRADING_ID \
  --source $EXECUTOR \
  --network testnet \
  -- execute_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --executor "$EXECUTOR"

echo "Upgrade executed successfully!"
```

### Step 10: Verify Upgrade Completion

```bash
# Confirm proposal is marked as executed
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected: status = Executed, executed = true
```

## Part 5: Parameter Updates (Governance-Controlled)

### Overview

Parameter changes now require a governance-approved flow with a 24-hour timelock. This ensures all critical configuration changes are auditable and safer to update.

### Step 11: Propose Parameter Change

```bash
# Example: Update rebalancing threshold
PARAMETER_KEY="rebal_threshold"  # Parameter to update
NEW_VALUE=750                     # New value in basis points (7.5%)

# Propose the parameter change (from ADMIN account)
PARAM_PROPOSAL_ID=$(stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- propose_parameter_change \
  --admin "$ADMIN" \
  --parameter_key "$PARAMETER_KEY" \
  --new_value "$NEW_VALUE" | grep -oP '\d+')

echo "Parameter Proposal ID: $PARAM_PROPOSAL_ID"
```

### Step 12: Execute Parameter Change (After Timelock)

```bash
# After 24-hour timelock, EXECUTOR can execute the parameter change
stellar contract invoke \
  --id $TRADING_ID \
  --source $EXECUTOR \
  --network testnet \
  -- execute_parameter_change \
  --proposal_id "$PARAM_PROPOSAL_ID"

echo "Parameter change executed successfully!"
```

### Step 13: Cancel Parameter Proposal (If Needed)

```bash
# ADMIN can cancel a parameter proposal before execution
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- cancel_parameter_proposal \
  --admin "$ADMIN" \
  --proposal_id "$PARAM_PROPOSAL_ID"

echo "Parameter proposal cancelled"
```

## Part 6: Handling Errors & Rejections

### Scenario A: Rejecting an Upgrade

```bash
# If APPROVER_2 disagrees, they can reject before threshold is met
stellar contract invoke \
  --id $TRADING_ID \
  --source $APPROVER_2 \
  --network testnet \
  -- reject_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --rejector "$APPROVER_2"

# Verify rejection
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected: status = Rejected
```

### Scenario B: Admin Cancels Proposal

```bash
# ADMIN can cancel any proposal before execution
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- cancel_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --admin "$ADMIN"

# Verify cancellation
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- get_upgrade_proposal \
  --proposal_id "$PROPOSAL_ID"

# Expected: status = Cancelled
```

### Scenario C: Preventing Duplicate Approval

```bash
# If APPROVER_1 tries to approve again
stellar contract invoke \
  --id $TRADING_ID \
  --source $APPROVER_1 \
  --network testnet \
  -- approve_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --approver "$APPROVER_1"

# Result: Error - DuplicateApproval
# Each signer can only approve once per proposal
```

## Part 7: Contract Pause/Unpause

### Emergency Pause

```bash
# ADMIN can pause contract during emergency
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- pause \
  --admin "$ADMIN"

echo "Contract paused - trading operations halted"
```

### Unpause After Mitigation

```bash
# After fixing issues, ADMIN can unpause
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- unpause \
  --admin "$ADMIN"

echo "Contract unpaused - trading operations resumed"
```

## Advanced: Multi-Proposal Management

### Tracking Multiple Proposals

```bash
# Script to check all active proposals
for prop_id in 1 2 3 4 5; do
  echo "=== Proposal $prop_id ==="
  stellar contract invoke \
    --id $TRADING_ID \
    --source $ADMIN \
    --network testnet \
    -- get_upgrade_proposal \
    --proposal_id "$prop_id" 2>/dev/null || echo "Not found"
done
```

### Parallel vs Sequential Upgrades

```
Sequential (Recommended):
  Proposal 1 → Execute → Proposal 2 → Execute

Parallel (Not Allowed):
  Proposal 1 (Pending)
  Proposal 2 (Pending)  ← Only one can execute at a time
  
Note: State must be migrated sequentially to maintain integrity
```

## Monitoring & Auditing

### Contract State Monitoring

```bash
# Create monitoring script
cat > monitor_upgrades.sh << 'EOF'
#!/bin/bash

TRADING_ID=$1
INTERVAL=${2:-60}  # Check every 60 seconds

while true; do
  echo "[$(date)] Checking contract state..."
  
  # Get current version
  VERSION=$(stellar contract invoke \
    --id $TRADING_ID \
    --source my-account \
    --network testnet \
    -- get_version)
  
  echo "Current Version: $VERSION"
  
  sleep $INTERVAL
done
EOF

chmod +x monitor_upgrades.sh
./monitor_upgrades.sh $TRADING_ID
```

### Governance Activity Log

```bash
# Log all upgrade proposals for audit trail
cat > audit_log.txt << 'EOF'
Date,ProposalID,Proposer,Status,Threshold,Approvals,ExecutionTime
EOF

# Append to log when proposals are created
for prop_id in 1 2 3 4 5; do
  stellar contract invoke \
    --id $TRADING_ID \
    --source $ADMIN \
    --network testnet \
    -- get_upgrade_proposal \
    --proposal_id "$prop_id" >> audit_log.txt 2>/dev/null
done
```

## Troubleshooting

### Issue: "Unauthorized" Error

```
Cause: Caller doesn't have required role
Solution: Verify the account has correct governance role
  • Admin: Can only call from admin address
  • Approver: Must be in proposal approvers list
  • Executor: Must match executor role
```

### Issue: "TimelockNotExpired" Error

```
Cause: Trying to execute before timelock delay has passed
Solution: 
  • Check proposal execution_time
  • Wait until current_time >= execution_time
  • Use: date +%s to check current timestamp
```

### Issue: "DuplicateApproval" Error

```
Cause: Approver trying to approve the same proposal twice
Solution:
  • Each approver can only vote once per proposal
  • Different approvers needed for additional votes
  • Use reject_upgrade() to change vote
```

### Issue: "InvalidThreshold" Error

```
Cause: Threshold > number of approvers
Solution:
  • Ensure approval_threshold <= approvers.len()
  • Example: 3-of-3 requires exactly 3 approvers
  • Example: 2-of-3 requires at least 3 approvers
```

### Issue: "ProposalNotActive" Error

```
Cause: Trying to execute or cancel a proposal that is already executed or cancelled
Solution:
  • Check proposal status before executing or cancelling
  • Only active (Pending) proposals can be executed or cancelled
```

## Best Practices

### For Admins
- ✅ Always use multi-sig (never 1-of-1)
- ✅ Include detailed descriptions in proposals
- ✅ Use minimum 24-hour timelocks on mainnet
- ✅ Test proposals on testnet first
- ✅ Communicate upgrades to community 48h in advance

### For Approvers
- ✅ Review all proposed changes before approving
- ✅ Verify contract hash matches official builds
- ✅ Check for security audit results
- ✅ Reject suspicious proposals immediately
- ✅ Coordinate with other signers out-of-band

### For the Executor
- ✅ Only execute after timelock expires
- ✅ Verify proposal status is Approved
- ✅ Monitor network conditions before execution
- ✅ Be prepared for emergency pause/cancellation

## Emergency Procedures

### If Malicious Upgrade Detected

```bash
# STEP 1: Before execution (within timelock)
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- cancel_upgrade \
  --proposal_id "$PROPOSAL_ID" \
  --admin "$ADMIN"

# STEP 2: Pause contract for safety
stellar contract invoke \
  --id $TRADING_ID \
  --source $ADMIN \
  --network testnet \
  -- pause \
  --admin "$ADMIN"

# STEP 3: Communicate to community
# - Announce security issue
# - Explain remediation steps
# - Propose safer upgrade path
```

### If Approved Upgrade Breaks Things

```bash
# Note: Cannot undo already-executed upgrade
# Contract code is immutable on-chain

# STEPS:
# 1. Pause the buggy contract
# 2. Migrate users to previous contract version (if available)
# 3. Deploy fixed V3
# 4. Propose new upgrade through governance
# 5. Once approved and timelocked, migrate to V3
```

## Testing Your Governance Setup

### Testnet Validation Checklist

- [ ] Create proposal with 2-of-3 multi-sig
- [ ] Have 2 approvers vote (reaches threshold)
- [ ] Verify status transitions to Approved
- [ ] Wait for timelock to expire
- [ ] Execute upgrade successfully
- [ ] Verify proposal marked as executed
- [ ] Test rejection flow with new proposal
- [ ] Test cancellation by admin
- [ ] Verify duplicate approval prevention
- [ ] Test pause/unpause functions
- [ ] Test parameter change proposal
- [ ] Test parameter change execution after timelock
- [ ] Test parameter change cancellation

### Pre-Mainnet Requirements

- [ ] All governance roles assigned to secure addresses
- [ ] Hardware wallet setup for multi-sig signers
- [ ] Minimum 24-hour timelock enforced
- [ ] Community governance document published
- [ ] Emergency escalation procedure documented
- [ ] Monitoring alerts configured
- [ ] Backup execution mechanisms in place
- [ ] User communication template prepared

---

**Last Updated**: January 22, 2026  
**Version**: 1.1  
**Status**: Active
