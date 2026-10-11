# Deployment Guide: Production Hardening and Orchestration

**Application**: Privacy-Preserving EHR Blockchain IDS & Healthcare SOC Dashboard  
**Architecture**: Python 3.11–3.14 / PyTorch MPS & CPU / Web3 / Streamlit Multi-Page UI  
**Containerization**: Docker Multi-Stage (`Dockerfile`, `docker-compose.yml`)  

---

## 1. System Requirements

### Minimum Hardware Specification (Edge Gateway / Lab Evaluation)
- **CPU**: 2 vCPUs (x86_64 or Apple Silicon ARM64)
- **RAM**: 4 GB System Memory (8 GB recommended for batch training)
- **Disk**: 5 GB available SSD storage (excluding raw 1.7 GB benchmark archive)
- **Accelerator**: Optional (Apple Silicon MPS or CUDA GPU acceleration automatically detected)

---

## 2. Deployment Targets

### 2.1 Option A: Local Bare-Metal Execution
```bash
# Clone & navigate to repo
git clone https://github.com/bhabadharish/Blockchain-EHR.git
cd Blockchain-EHR

# Create isolated Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run automated tests to verify environment
pytest tests/ -q

# Launch Streamlit SOC application
streamlit run app.py --server.port=8501 --server.address=0.0.0.0
```
Access the application at `http://localhost:8501`.

### 2.2 Option B: Docker Container Deployment
The repository includes a production-hardened `Dockerfile` utilizing a non-root unprivileged user (`appuser`), multi-stage layer caching, and built-in health monitoring.

```bash
# Build the production container image
docker build -t blockchain-ehr-soc:latest .

# Run container with resource limits
docker run -d \
  --name blockchain-ehr-soc \
  -p 8501:8501 \
  --restart unless-stopped \
  --memory="4g" \
  --cpus="2.0" \
  blockchain-ehr-soc:latest
```

### 2.3 Option C: Docker Compose Orchestration
```bash
docker-compose up -d --build
```
Check status:
```bash
docker-compose ps
docker-compose logs -f
```

---

## 3. Configuration & Environment Variables

Copy `.env.example` to `.env` to customize settings:

```bash
cp .env.example .env
```

| Environment Variable | Default Value | Description |
| :--- | :---: | :--- |
| `BLOCKCHAIN_RPC_URL` | `http://127.0.0.1:8545` | EVM JSON-RPC endpoint (Ganache / Hardhat / Ethereum node) |
| `CHAIN_ID` | `1337` | EVM Network Chain ID |
| `RANDOM_SEED` | `42` | Seed for deterministic reproducible execution |
| `DEVICE` | `auto` | PyTorch execution backend (`mps`, `cuda`, `cpu`, or `auto`) |
| `QBER_THRESHOLD` | `0.11` | BB84 QKD simulated abort threshold (11%) |
| `SIMULATION_MODE` | `true` | Fallback in-memory ledger when no live EVM node is detected |
| `STREAMLIT_SERVER_PORT`| `8501` | Application port |
| `STREAMLIT_SERVER_HEADLESS` | `true` | Headless execution mode for containers and cloud servers |

---

## 4. Health Monitoring & Observability

The container exposes a built-in healthcheck endpoint:
- **URL**: `http://localhost:8501/_stcore/health`
- **Response**: `200 OK`
- **Docker Healthcheck**: Configured to poll every 30s with a 10s timeout and 3 retries.

---

## 5. Security Hardening Checklist

1. **Non-Root Execution**: Container runs under unprivileged `appuser` (UID 999).
2. **Secrets Hygiene**: Zero hardcoded private keys or tokens; credentials passed strictly via environment variables.
3. **Data Protection**: Raw EHR records undergo client-side sanitization and AES-256-GCM encryption before transport.
4. **Network Exposure**: In production, terminate TLS via reverse proxy (Nginx, Traefik, or AWS ALB) in front of port 8501.
