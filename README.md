# devops-lab

A hands-on DevOps + Security learning lab running on Raspberry Pi 5.

## Stack

| Layer | Tool |
|-------|------|
| App | Go (HTTP API) |
| Container | Docker |
| Orchestration | k3s (single-node Kubernetes) |
| CI | GitHub Actions — test, lint, build |
| CD | GitHub Actions — push to GHCR, deploy to Pi |
| Metrics | Prometheus + Grafana |
| Logs | Loki + Promtail |
| Attack scripts | Python |

---

## Quick Start

### 1. Reboot Pi (required once — enables memory cgroup for k3s)
```bash
sudo reboot
```

### 2. Verify k3s is running
```bash
sudo kubectl get nodes
sudo kubectl get pods -A
```

### 3. Deploy the app
```bash
# Import local Docker image into k3s
docker save devops-lab:latest | sudo k3s ctr images import -

# Apply manifests
sudo kubectl apply -f k8s/
sudo kubectl get pods -n devops-lab -w
```

### 4. Access the app
```bash
# NodePort — accessible at Pi's IP:30080
curl http://localhost:30080/
curl http://localhost:30080/health
curl http://localhost:30080/metrics
```

### 5. Run as plain Docker container (no k3s needed)
```bash
docker run --rm -p 8080:8080 devops-lab:latest
```

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Hello response with hostname + version |
| GET | `/health` | Liveness probe |
| GET | `/ready` | Readiness probe |
| GET | `/metrics` | Prometheus metrics |
| GET | `/slow?ms=N` | Artificial delay (max 5000ms) |
| POST | `/login` | Fake login (username/password JSON) |
| GET | `/admin` | Restricted endpoint (needs Bearer token) |

---

## Simulations

### Normal traffic
```bash
python3 scripts/traffic_sim.py --url http://localhost:30080 --rps 20 --duration 120
```

### HTTP flood (DoS)
```bash
python3 scripts/attack_flood.py --url http://localhost:30080 --workers 50 --duration 60
```

### Brute-force login
```bash
python3 scripts/attack_bruteforce.py --url http://localhost:30080
```

### Recon / path traversal
```bash
python3 scripts/attack_pathtraversal.py --url http://localhost:30080
```

### Check metrics from terminal
```bash
python3 scripts/check_metrics.py --prometheus http://localhost:9090
```

---

## CI/CD

- Push to any branch → runs tests + lint
- Push to `main` → builds ARM64 Docker image, pushes to GHCR, deploys to Pi

### Self-hosted runner setup (Pi)
```bash
# Follow GitHub → Settings → Actions → Runners → New self-hosted runner
# The Pi will receive deploys automatically on every push to main
```

### Secrets required in GitHub repo
| Secret | Value |
|--------|-------|
| `GITHUB_TOKEN` | Auto-provided by Actions |

---

## Grafana Dashboard

Import `grafana/dashboard.json` via Grafana → Dashboards → Import.

Panels:
- Request rate by path
- Latency p50/p99
- Error rate by status code
- Login attempts / brute-force indicator
- Rate limit hits (429) — attack indicator
- Active connections
- Pod count (watch HPA scale up under load)
- App CPU usage

---

## Security Measures (to explore)

1. **Rate limiting** — built into the app (per-IP, configurable)
2. **Network policies** — `k8s/networkpolicy.yaml` (apply after attack demo)
3. **Non-root container** — `runAsUser: 65534`, `readOnlyRootFilesystem: true`
4. **Dropped capabilities** — `capabilities.drop: [ALL]`
5. **Resource limits** — prevents a single pod from starving the Pi

---

## File Structure

```
devops-lab/
├── app/
│   ├── main.go          # Go HTTP service
│   ├── main_test.go     # Unit tests
│   ├── Dockerfile       # Multi-stage, scratch base, ARM64
│   ├── go.mod
│   └── go.sum
├── k8s/
│   ├── namespace.yaml
│   ├── deployment.yaml  # 2 replicas, resource limits, probes
│   ├── service.yaml     # NodePort 30080
│   ├── hpa.yaml         # Scale 2→8 pods on CPU/memory
│   ├── networkpolicy.yaml
│   └── servicemonitor.yaml
├── scripts/
│   ├── traffic_sim.py       # Normal load
│   ├── attack_flood.py      # HTTP flood
│   ├── attack_bruteforce.py # Login brute-force
│   ├── attack_pathtraversal.py # Recon probe
│   └── check_metrics.py     # Terminal Prometheus dashboard
├── grafana/
│   └── dashboard.json   # Import into Grafana
├── .github/
│   └── workflows/
│       ├── ci.yaml      # Test + lint on every push
│       └── cd.yaml      # Build ARM64 image + deploy on main
└── README.md
```
