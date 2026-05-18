# EDEN-BioGuard Production Deployment Guide

**Target:** On-premise Linux server  
**Architecture:** Full stack (API + dashboards + blockchain contracts)  
**Scale:** Single server pilot deployment  
**Status:** Ready for production

---

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Linux server (Ubuntu 22.04 LTS recommended, 4GB+ RAM, 50GB+ disk)
- Docker & Docker Compose installed
- Git
- (Optional) Planetary Computer API key
- (Optional) Ethereum testnet RPC endpoint

### Step 1: Clone & Setup
```bash
git clone https://github.com/waren23greg-stack/EDEN-BioGuard.git
cd EDEN-BioGuard

# Copy environment template
cp .env.example .env

# Edit configuration (see below)
nano .env
```

### Step 2: Configure Environment
Edit `.env` with your settings:

```bash
# Essential configs
EDEN_COMMUNICATIONS_HOST=0.0.0.0
EDEN_COMMUNICATIONS_PORT=8000
EDEN_COMMUNICATIONS_ALLOWED_ORIGINS=http://your-server-ip,http://localhost

# Live feeds (auto-enabled)
# WHO AFRO and Africa CDC feeds will be fetched automatically

# Planetary Computer API (for NDVI satellite imagery)
PLANETARY_COMPUTER_API_KEY=your_api_key_here

# Blockchain (testnet for pilot)
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/YOUR_INFURA_KEY
WEB3_PROVIDER_NETWORK=sepolia
WEB3_PRIVATE_KEY=your_private_key_here

# Other configs as needed
```

### Step 3: Build & Deploy
```bash
# Build Docker images
docker-compose build

# Start all services
docker-compose up -d

# Verify all services are running
docker-compose ps

# Check logs
docker-compose logs -f api
```

### Step 4: Verify Deployment
```bash
# Health check
curl http://localhost:8000/health

# View dashboards
# Navigate to http://your-server-ip in your browser

# Check feed ingestion logs
docker-compose logs feed-ingestion | tail -20

# Check COVENANT ledger
ls -lh data/covenant_ledger.json
```

---

## 📋 Detailed Configuration

### 1. Environment Variables

#### API Configuration
```env
# Listen on all interfaces (for remote access)
EDEN_COMMUNICATIONS_HOST=0.0.0.0
EDEN_COMMUNICATIONS_PORT=8000

# CORS - add your server IP/domain
EDEN_COMMUNICATIONS_ALLOWED_ORIGINS=http://192.168.1.100,http://localhost:3000,https://eden.yourdomain.com

# Data paths (inside Docker container)
EDEN_COMMUNICATIONS_DB_PATH=/data/communications/records.json
EDEN_DATA_ROOT=/data
EDEN_LIVE_INCIDENTS_PATH=/data/raw/live_incidents.csv
EDEN_COVENANT_LEDGER_PATH=/data/covenant_ledger.json
```

#### Live Feeds Configuration
```env
# These are auto-enabled (no API keys needed)
EDEN_WHO_AFRO_FEED=https://www.afro.who.int/rss.xml
EDEN_AFRICA_CDC_FEED=https://africacdc.org/tag/epidemic-intelligence/feed/

# ReliefWeb (optional)
EDEN_RELIEFWEB_API=https://reliefweb.int/api/v2/disasters
EDEN_RELIEFWEB_APPNAME=eden-bioguard
```

#### Planetary Computer API (For Satellite NDVI Data)
```bash
# Get API key:
# 1. Visit: https://planetarycomputer.microsoft.com/
# 2. Sign up for free tier
# 3. Create API key from dashboard
# 4. Add to .env:
PLANETARY_COMPUTER_API_KEY=your_api_key_from_planetary_computer

# Optional: Configure bounding box for East Africa
EDEN_NDVI_BBOX_EAST_AFRICA_LAT_MIN=-12
EDEN_NDVI_BBOX_EAST_AFRICA_LAT_MAX=5
EDEN_NDVI_BBOX_EAST_AFRICA_LON_MIN=28
EDEN_NDVI_BBOX_EAST_AFRICA_LON_MAX=42
```

#### Blockchain & Smart Contracts

##### Testnet Setup (Recommended for Pilot)
```bash
# 1. Get free testnet ETH from Sepolia faucet:
#    https://sepoliafaucet.com/

# 2. Set up Web3 provider (Infura example):
WEB3_PROVIDER_URL=https://sepolia.infura.io/v3/YOUR_INFURA_KEY
WEB3_PROVIDER_NETWORK=sepolia

# 3. Set your Sepolia wallet private key (the account that will deploy contracts)
#    Generate with: python -c "from eth_account import Account; a=Account.create(); print(f'Private Key: {a.key.hex()}'); print(f'Address: {a.address}')"
WEB3_PRIVATE_KEY=0xYOUR_PRIVATE_KEY_HEX

# 4. After deploying contracts, add their addresses:
CONTRACT_CONSERVATION_FRAUD_ADDRESS=0x...
CONTRACT_CORPORATE_INTRUSION_ADDRESS=0x...
CONTRACT_DISPLACEMENT_LEDGER_ADDRESS=0x...
CONTRACT_WHISTLEBLOWER_REWARD_ADDRESS=0x...
```

##### Mainnet Setup (Production Only)
```bash
# Use only after thorough testing on testnet
WEB3_PROVIDER_URL=https://mainnet.infura.io/v3/YOUR_INFURA_KEY
WEB3_PROVIDER_NETWORK=mainnet
WEB3_PRIVATE_KEY=0xYOUR_PRODUCTION_PRIVATE_KEY
```

### 2. Deploy Smart Contracts

```bash
# Access the contracts directory
cd contracts/

# Install Hardhat and dependencies
npm install -D hardhat @nomicfoundation/hardhat-toolbox

# Create Hardhat project
npx hardhat init

# Deploy to testnet
npx hardhat run scripts/deploy.js --network sepolia

# Output will give you contract addresses - add to .env
```

### 3. Nginx Configuration

The `nginx.conf` file is automatically loaded from Docker. For production HTTPS:

```bash
# Generate SSL certificate (self-signed for testing)
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem

# For production, use Let's Encrypt:
# https://letsencrypt.org/
```

---

## 🔧 Post-Deployment Tasks

### 1. Verify Live Feeds Are Working
```bash
# Check live incidents file
docker exec eden-feed-ingestion ls -lh /data/raw/live_incidents.csv

# View last fetched incidents
docker exec eden-feed-ingestion python -c \
  "import pandas as pd; df = pd.read_csv('/data/raw/live_incidents.csv'); print(df.head())"
```

### 2. Monitor COVENANT Ledger
```bash
# View blockchain ledger integrity
docker exec eden-covenant python covenant_engine.py \
  --ledger /data/covenant_ledger.json

# Output shows:
# - Chain verification status (INTACT/BROKEN)
# - Finding counts
# - Risk velocity (RISING/STABLE/FALLING)
```

### 3. Access Dashboards
- **Geospatial Map:** http://your-server-ip/dashboards/btu_map.html
- **Software-Ecological Timeline:** http://your-server-ip/dashboards/software_ecological_dashboard.html
- **API Health:** http://your-server-ip/health

### 4. Test API Endpoints
```bash
# Send a test communication
curl -X POST http://localhost:8000/api/communications/send \
  -H "Content-Type: application/json" \
  -d '{
    "messageType": "incident_alert",
    "recipients": ["stakeholders"],
    "referenceCode": "TEST-001",
    "subject": "Test Alert",
    "body": "This is a test alert",
    "severity": "MEDIUM"
  }'

# Get communication status
curl http://localhost:8000/api/communications/TEST-001/status
```

---

## 📊 Service Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        EDEN-BioGuard Stack                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Nginx      │  │ API Service  │  │ Feed Ingest  │      │
│  │  (Port 80)   │  │ (Port 8000)  │  │ (Background) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                            │                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboards  │  │  Dashboard   │  │  COVENANT    │      │
│  │   (HTML/JS)  │  │  Generator   │  │   Engine     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                            │                                 │
│                    ┌───────────────┐                        │
│                    │  Data Storage │                        │
│                    │  (/data/**)    │                        │
│                    └───────────────┘                        │
│                            │                                 │
│              ┌─────────────┴──────────────┐                 │
│              │                            │                 │
│         ┌─────────┐              ┌─────────────────┐        │
│         │ WHO/CDC │              │ Planetary Comp. │        │
│         │  Feeds  │              │ (Sentinel-2)    │        │
│         └─────────┘              └─────────────────┘        │
│                                                              │
│         ┌────────────────────────────────────┐              │
│         │  Blockchain (Ethereum Testnet)     │              │
│         │  - ConservationFraud.sol           │              │
│         │  - CorporateIntrusion.sol          │              │
│         │  - DisplacementLedger.sol          │              │
│         │  - WhistleblowerReward.sol         │              │
│         └────────────────────────────────────┘              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Checklist

- [ ] Change default CORS origins to your server IP/domain
- [ ] Use `.env` for secrets (never commit to git)
- [ ] Enable HTTPS with valid SSL certificate (nginx.conf has section)
- [ ] Run services as non-root user (Dockerfile uses `eden` user)
- [ ] Restrict API access with rate limiting (nginx.conf configured)
- [ ] Use testnet for contract deployment initially
- [ ] Rotate private keys regularly
- [ ] Monitor logs for suspicious activity
- [ ] Enable firewall rules (only expose 80/443)
- [ ] Use environment variables for all secrets

### Firewall Rules (Linux)
```bash
# Allow only SSH, HTTP, HTTPS
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS
sudo ufw enable
```

---

## 📈 Scaling & Optimization

### Single Server (Current)
- All services on one container host
- Suitable for: Pilot deployments, dev/test
- Capacity: ~10K events/day, 100s concurrent users

### Multi-Node (Future)
- Separate API, ingestion, and ledger nodes
- Load balancer (Nginx/HAProxy)
- Distributed PostgreSQL database
- Kubernetes orchestration

### Performance Tuning
```bash
# Increase Nginx worker connections
worker_connections 2048

# Tune Docker memory limits
docker-compose.yml: mem_limit: 4g

# Add caching layer (Redis)
# Extend docker-compose.yml with Redis service
```

---

## 🐛 Troubleshooting

### Services won't start
```bash
# Check Docker logs
docker-compose logs api
docker-compose logs feed-ingestion

# Verify ports aren't in use
lsof -i :80 -i :8000 -i :443
```

### Live feeds not updating
```bash
# Check feed connectivity
docker exec eden-feed-ingestion python -c \
  "import requests; print(requests.get('https://www.afro.who.int/rss.xml').status_code)"

# Manually run feed intake
docker exec eden-feed-ingestion python -m src.ingestion.feed_intake
```

### Blockchain contract deployment failed
```bash
# Check Web3 provider connectivity
docker exec eden-covenant python -c \
  "from web3 import Web3; print(Web3(Web3.HTTPProvider('$WEB3_PROVIDER_URL')).is_connected())"

# Verify testnet ETH balance
# Use Sepolia block explorer: https://sepolia.etherscan.io/
```

### Planetary Computer API errors
```bash
# Verify API key
docker exec eden-dashboard-gen python -c \
  "import os; print('Key set:', bool(os.getenv('PLANETARY_COMPUTER_API_KEY')))"

# Test Sentinel-2 query
docker exec eden-dashboard-gen python -m src.visualization.geo_dashboard --dry-run
```

---

## 🚨 Monitoring & Logging

### Real-time Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api

# Last 100 lines
docker-compose logs --tail=100 feed-ingestion
```

### Log Rotation
Logs are stored in `./logs/` and rotated automatically (see LOG_MAX_BYTES in .env).

### Health Checks
```bash
# Automated health checks every 30s
# View in docker-compose.yml healthcheck sections

# Manual health check
curl -v http://localhost:8000/health
curl -v http://localhost:80/health
```

---

## 📦 Backup & Restore

### Backup Data
```bash
# Backup all data and ledger
tar -czf eden-backup-$(date +%Y%m%d-%H%M%S).tar.gz data/

# Backup only covenant ledger
cp data/covenant_ledger.json covenant_ledger-backup.json

# Backup communications records
cp data/communications/records.json communications-backup.json
```

### Restore From Backup
```bash
# Stop services
docker-compose down

# Restore data
tar -xzf eden-backup-YYYYMMDD-HHMMSS.tar.gz

# Start services
docker-compose up -d
```

---

## 🔄 Updates & Maintenance

### Update EDEN-BioGuard
```bash
# Pull latest code
git pull origin main

# Rebuild images
docker-compose build --no-cache

# Restart services (zero-downtime with rolling restart)
docker-compose up -d
```

### Update Dependencies
```bash
# Update requirements.txt to latest versions
pip list --outdated
pip install --upgrade -r requirements.txt
pip freeze > requirements.txt

# Rebuild Docker image
docker-compose build
```

---

## 📞 Support & Issues

### Community Resources
- **GitHub Issues:** https://github.com/waren23greg-stack/EDEN-BioGuard/issues
- **Documentation:** `/docs` directory
- **Contributing:** See `CONTRIBUTING.md`

### Common Issues
1. **Port already in use:** Change ports in docker-compose.yml
2. **Out of disk space:** Expand volume with `docker volume prune`
3. **Memory issues:** Increase Docker memory limit in docker-compose.yml
4. **Feed fetch failures:** Check internet connectivity, firewall rules

---

## 📊 Next Steps

1. ✅ Verify all services are running
2. ✅ Check live feeds are fetching data
3. ✅ Access dashboards and verify data display
4. ✅ Deploy smart contracts to testnet
5. ✅ Send test communications via API
6. ✅ Monitor logs for errors
7. ✅ Set up automated backups
8. ✅ Plan for production SSL certificates
9. ✅ Test failover & disaster recovery
10. ✅ Document any customizations made

---

## 📝 License & Attribution

See LICENSE file for details.

**Maintained by:** EDEN-BioGuard Development Team  
**Last Updated:** 2026-05-18  
**Status:** Active Development - Production Ready
