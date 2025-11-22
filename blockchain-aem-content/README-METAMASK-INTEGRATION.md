# Oak Chain Publishing with MetaMask Integration

## Overview

This POC demonstrates blockchain-backed content publishing where users pay Oak validators with cryptocurrency (ETH/USDC) via MetaMask, and validators replicate content across a decentralized Oak repository using Aeron consensus.

## Architecture

```
┌──────────────┐
│ AEM Author   │
│ (Sling)      │
└──────┬───────┘
       │
       │ 1. User clicks "Publish to Oak Chain"
       ↓
┌──────────────────────┐
│ oak-chain-publish.html│
│ (Web3.js + MetaMask) │
└──────┬───────────────┘
       │
       │ 2. MetaMask popup: Pay 0.001-0.01 ETH
       ↓
┌────────────────────────────────┐
│ ValidatorPaymentV3_1.sol       │
│ (Ethereum Smart Contract)       │
└──────┬─────────────────────────┘
       │
       │ 3. Emit ProposalPaid event
       ↓
┌──────────────────────────────────┐
│ Oak Validators (3 nodes)         │
│ - Listen for blockchain events   │
│ - Verify payment                 │
│ - Queue content by tier          │
│ - Replicate via Aeron consensus │
└──────┬───────────────────────────┘
       │
       │ 4. Content replicated to all peers
       ↓
┌──────────────────────────┐
│ /oak-chain/content/{path}│
│ (Global read-only mount) │
└──────────────────────────┘
```

## Features

### Tier-Based Pricing
- **Standard** (0.001 ETH / ~$3.25): 60s delay, batch-friendly
- **Express** (0.002 ETH / ~$6.50): 15s delay, priority queue
- **Priority** (0.01 ETH / ~$32.50): 5s delay, instant processing

### Payment Options
- **ETH**: Native Ethereum payments
- **USDC**: Stablecoin for enterprises (avoids volatility)

### Validator Economics
- Payments distributed to validator pool via shares (33.3% each)
- Pull-payment model (validators withdraw accumulated fees)
- Batch discounts (10% off for 10+ proposals)

## Files Created

### Frontend
- **`oak-chain-publish.html`**: MetaMask integration UI
  - Web3.js 4.3.0 for blockchain interaction
  - Tier selector (Standard/Express/Priority)
  - Cost summary with gas estimation
  - Transaction status tracking

### Backend
- **`OakChainPublishServlet.java`**: Content submission handler
  - Receives content after MetaMask payment
  - Logs proposal metadata for validator processing
  - Returns status and expected content path

### Smart Contract
- **`ValidatorPaymentV3_1.sol`**: Production-ready payment router
  - Multi-currency (ETH + USDC)
  - Validator preference routing
  - Batch payment support
  - DoS-resistant (batch size cap)
  - Audited and mainnet-ready

## Setup Instructions

### 1. Deploy Smart Contract (Sepolia Testnet)

```bash
cd blockchain-smart-contracts

# Install dependencies
npm install

# Deploy to Sepolia
npx hardhat run scripts/deploy-v3_1.js --network sepolia

# Copy deployed address
# Example output: ValidatorPaymentV3_1 deployed to: 0x123...
```

### 2. Update Frontend Configuration

Edit `oak-chain-publish.html`:

```javascript
// Line 227: Update with your deployed contract address
const CONTRACT_ADDRESS = '0x...'; // <-- Replace with Sepolia address
```

### 3. Configure Validators (Production)

Validators would listen for `ProposalPaid` events:

```java
// In validator startup
web3j = Web3j.build(new HttpService("https://sepolia.infura.io/v3/YOUR_KEY"));
contract = ValidatorPaymentV3_1.load(CONTRACT_ADDRESS, web3j, ...);

contract.proposalPaidEventFlowable(DefaultBlockParameterName.LATEST, DefaultBlockParameterName.LATEST)
    .subscribe(event -> {
        String proposalId = event.proposalId;
        int tier = event.tier.intValue();
        
        // Queue content write based on tier
        proposalQueue.add(proposalId, tier, getTierDelay(tier));
    });
```

### 4. Rebuild & Deploy Sling

```bash
cd sling-org-apache-sling-starter
mvn clean package -DskipTests

# Start Sling
./scripts/run-sling-local.sh 4502 http://localhost:8090
```

### 5. Access the UI

- **Main Dashboard**: http://localhost:4502/content/blockchain-aem/blockchain.html
- **MetaMask Publishing**: http://localhost:4502/content/blockchain-aem/oak-chain-publish.html

## Testing (POC Mode)

### MetaMask Setup (Sepolia Testnet)

1. Install MetaMask extension
2. Create/import wallet
3. Switch to Sepolia testnet
4. Get free test ETH: https://sepoliafaucet.com/

### Test Flow

1. Open `oak-chain-publish.html`
2. Click "Connect MetaMask"
3. Fill content form:
   - Path: `/content/my-page`
   - Title: `My Test Content`
   - Content: `Hello Oak Chain!`
4. Select tier (Standard for testing)
5. Click "Pay with MetaMask & Publish"
6. Approve transaction in MetaMask
7. Wait for confirmation (~15s on Sepolia)
8. Content queued for validator processing

### Expected Logs

**Sling logs** (`launcher/logs/error.log`):
```
Oak Chain publish request received:
  Path: /content/my-page
  Title: My Test Content
  Proposal ID: 0xabc123...
  Tx Hash: 0xdef456...
  Tier: 0
  Wallet: 0x789abc...
✅ Mock: Content would be written to /oak-chain/content/my-page after validator processing
```

**Validator logs** (`oak-chain/logs/validator-0.log`):
```
📥 ProposalPaid event detected: 0xabc123...
   Payer: 0x789abc...
   Tier: STANDARD
   Amount: 0.001 ETH
🔄 Queuing content write (60s delay)
✅ Content written to /oak-chain/content/my-page
🌐 Replicating via Aeron consensus...
```

## Security Considerations

### Smart Contract (Audited ✅)
- ✅ ReentrancyGuard on all payment functions
- ✅ Pull payment model (no push to prevent DoS)
- ✅ Proposal ID uniqueness check (prevents replay)
- ✅ Batch size cap (prevents gas DoS)
- ✅ Separate ETH/USDC accounting (no cross-currency bugs)

### Validator Payment Verification
Validators MUST verify blockchain events before processing:

```java
// Verify ProposalPaid event exists on-chain
TransactionReceipt receipt = web3j.ethGetTransactionReceipt(txHash).send();
List<Log> logs = receipt.getLogs();
boolean validPayment = logs.stream()
    .anyMatch(log -> log.getTopics().get(0).equals(PROPOSAL_PAID_TOPIC));

if (!validPayment) {
    throw new SecurityException("Payment verification failed");
}
```

## Cost Analysis

### Typical Transaction Costs (Sepolia/Mainnet)

| Tier | Validator Payment | Est. Gas (Gwei) | Total Cost |
|------|-------------------|-----------------|------------|
| Standard | 0.001 ETH (~$3.25) | ~0.0005 ETH | ~$4.90 |
| Express | 0.002 ETH (~$6.50) | ~0.0005 ETH | ~$8.15 |
| Priority | 0.01 ETH (~$32.50) | ~0.0005 ETH | ~$34.12 |

### Batch Discount (10+ proposals)
- 10% discount on validator payment
- Example: 10x Standard = 0.009 ETH (save 0.001 ETH)

## Production Deployment Checklist

- [ ] Deploy `ValidatorPaymentV3_1` to mainnet
- [ ] Configure validator endpoints in contract
- [ ] Set up validator event listeners (Web3j/ethers.js)
- [ ] Implement blockchain payment verification
- [ ] Add wallet-signed write proposals
- [ ] Configure Aeron consensus for multi-validator replication
- [ ] Set up monitoring (transaction success rate, queue depth)
- [ ] Document emergency pause procedures
- [ ] Establish validator fee withdrawal schedule

## Known Limitations (POC)

1. **No actual blockchain verification**: Servlet logs proposal but doesn't verify payment
2. **No write proposal submission**: Content not actually written to validators
3. **Mock contract address**: Needs real Sepolia/mainnet deployment
4. **No event listener**: Validators don't actually listen for ProposalPaid events

## Future Enhancements

1. **USDC Payment Support**: Add `payForProposalUSDC()` option
2. **Batch Publishing**: Upload multiple pages at once (10% discount)
3. **Validator Preference**: Let users select low-latency validators
4. **Transaction Dashboard**: Show all user's published content + status
5. **Content Diff Preview**: Show what will be replicated before payment

## References

- Smart Contract Audit: `Blockchain-AEM/10-smart-contracts/FINAL-AUDIT-SIGN-OFF.md`
- ValidatorPayment Docs: `blockchain-smart-contracts/README-ValidatorPaymentV3_1.md`
- Oak Consensus: `jackrabbit-oak/oak-segment-consensus/README.md`
- Sling Starter: `sling-org-apache-sling-starter/README.md`

## Support

For issues or questions:
- Smart contract: Review audit doc and contract comments
- Frontend: Check browser console for Web3 errors
- Backend: Check Sling logs (`launcher/logs/error.log`)
- Validators: Check validator logs (`oak-chain/logs/validator-*.log`)

