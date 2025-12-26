# 🖥️ server_monitoring.sh

> 통합 서버 모니터링 스크립트 (2025)

---

## 📋 개요

**`server_monitoring.sh`** - 이 저장소의 **메인 스크립트**입니다.

cron으로 주기적 실행하면 시스템 리소스, 네트워크, 서비스, 컨테이너, SSH 보안 등을
자동 감시하고 문제 발생 시 관리자에게 즉시 알림을 전송합니다.

> 📌 **핵심**: 일반 사용자는 `server_monitoring.sh` **하나만** 실행하면 됩니다.
> `srv_monitor/`, `backup_scripts/`는 특수 상황용 **보조 스크립트**입니다.

---

## 🚀 빠른 시작

```bash
# 메인 스크립트 실행 (이것만 하면 됩니다)
sudo ./server_monitoring.sh

# cron 등록 (15분마다 자동 실행)
sudo crontab -e
# 아래 줄 추가:
*/15 * * * * /path/to/server_monitoring.sh >> /var/log/monitoring.log 2>&1
```

> 💡 **일반 사용자는 위 명령만으로 충분합니다.**
> 아래 보조 스크립트들은 특수 상황에서만 필요합니다.

---

## ✨ 주요 기능

| 카테고리 | 기능 |
|----------|------|
| **시스템 리소스** | CPU, 메모리, 디스크, 네트워크 모니터링 |
| **SSH 보안** | 브루트포스 공격 탐지, Fail2Ban 연동, 세션 감시 |
| **Docker/컨테이너** | 상태, 볼륨 사용량, 로그 분석 |
| **서비스 상태** | systemd 서비스 자동 재시작 |
| **알림** | Slack + Email 통합 알림 (중복 방지) |
| **로그 관리** | 자동 압축, 오래된 로그 정리 |

---

## 📁 파일 구조

### 🔴 메인 스크립트 (필수)

| 파일 | 설명 |
|------|------|
| **`server_monitoring.sh`** | **메인 통합 스크립트** - cron 등록하여 사용 |

### 🟡 보조 스크립트 (선택적)

| 폴더 | 용도 | 언제 사용? |
|------|------|-----------|
| `srv_monitor/` | 개별 모니터링 도구 | 특정 항목만 빠르게 확인할 때 |
| `backup_scripts/` | 백업 자동화 | Label Studio 등 별도 백업 필요시 |

### 🟢 기타 파일

| 파일 | 설명 |
|------|------|
| `gpu_inspect.sh` | GPU 프로세스 추적 |
| `install_monitoring_suite.sh` | 의존성 자동 설치 |

### 전체 디렉토리

```
opt_script/
├── server_monitoring.sh           # 🔴 메인 스크립트
├── gpu_inspect.sh
├── install_monitoring_suite.sh
├── README.md
│
├── srv_monitor/                   # 🟡 개별 모니터링 (선택적)
│   ├── disk_monitor_quick.sh
│   ├── disk_monitor_detail.sh
│   ├── docker_prune_check.sh
│   ├── container_size_check.sh
│   ├── monitor_iftop.sh
│   └── nas_monitor_regular.sh
│
├── backup_scripts/                # 🟡 백업 스크립트 (선택적)
│   ├── transfer_data.sh
│   └── label_studio_export_backup.py
│
└── log/                           # 로그 디렉토리
    ├── global_YYYY-MM-DD.log
    ├── ssh_security_YYYY-MM-DD.log
    ├── alerts_YYYY-MM-DD.log
    └── archive/
```

---

## 🔧 설치 및 설정

### 필수 패키지 설치

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y bc mailutils curl wget

# 선택적 (기능 향상)
sudo apt-get install -y lm-sensors ifstat sysstat fail2ban
```

### 환경변수 설정 (권장)

```bash
# /etc/environment 또는 ~/.bashrc에 추가
export HOST_ID="production-server-01"
export ALERT_EMAIL="ops@company.com"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

> ⚠️ **보안 주의**: `SLACK_WEBHOOK_URL`은 스크립트에 직접 기록하지 마세요.

### 스크립트 설정

스크립트는 환경변수로 오버라이드 가능:

```bash
HOST_ID="${HOST_ID:-sv3}"
ALERT_EMAIL="${ALERT_EMAIL:-admin@company.com}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"  # 환경변수 필수
LOG_BASE="${LOG_BASE:-${SCRIPT_DIR}/log}"
```

---

## 📅 사용법

### 수동 실행

```bash
# 전체 모니터링
sudo ./server_monitoring.sh

# SSH 모니터링만
sudo ./server_monitoring.sh ssh_only

# 요약 보고서만
sudo ./server_monitoring.sh summary_only
```

### 자동 실행 (Crontab)

```bash
sudo crontab -e

# 매 15분마다 실행
*/15 * * * * /path/to/server_monitoring.sh >> /var/log/monitoring.log 2>&1

# 매일 오전 9시 요약 보고서
0 9 * * * /path/to/server_monitoring.sh summary_only
```

---

## 🚨 알림 시스템

### 알림 레벨

| 레벨 | 설명 | Email | Slack |
|------|------|-------|-------|
| **INFO** | 정보성 | ❌ | ❌ |
| **WARN** | 경고 | ✅* | ✅ |
| **CRIT** | 치명적 | ✅ | ✅ |

*WARN 이메일은 `SEND_WARN_EMAILS=true` 설정시만 전송*

### 주요 알림 케이스

- **SSH Brute Force Attempt**: 로그인 실패 임계값 초과
- **Disk Usage Critical**: 디스크 사용량 위험 수준
- **Service Down**: 중요 서비스 다운
- **Container Error Spike**: 컨테이너 에러 급증

---

## 🛡️ SSH 보안 및 Fail2Ban

### 차단 IP 확인

```bash
fail2ban-client status sshd | grep 'Banned IP list'
```

### IP 차단 해제

```bash
sudo fail2ban-client set sshd unbanip <IP주소>
```

### Whitelist 설정

`/etc/fail2ban/jail.local`:
```ini
[sshd]
ignoreip = 127.0.0.1 192.168.0.0/16 <회사IP대역>
```

---

## 📂 보조 스크립트 상세 사용법

> ⚠️ **주의**: 아래 스크립트들은 `server_monitoring.sh`에서 **자동 호출되지 않습니다**.
> 필요시 수동 실행하거나 별도 cron으로 등록하세요.

### srv_monitor/ - 개별 모니터링 도구

**언제 사용하나요?**
- `server_monitoring.sh`는 전체 스캔이라 무거움
- 특정 항목만 빠르게 확인하고 싶을 때

| 스크립트 | 용도 | 실행 예시 |
|----------|------|----------|
| `disk_monitor_quick.sh` | 디스크 빠른 체크 | `./srv_monitor/disk_monitor_quick.sh` |
| `disk_monitor_detail.sh` | 디스크 상세 분석 | `./srv_monitor/disk_monitor_detail.sh` |
| `docker_prune_check.sh` | Docker 정리 전 확인 | `./srv_monitor/docker_prune_check.sh` |
| `container_size_check.sh` | 컨테이너별 용량 | `./srv_monitor/container_size_check.sh` |
| `monitor_iftop.sh` | 네트워크 트래픽 | `./srv_monitor/monitor_iftop.sh` |
| `nas_monitor_regular.sh` | NAS 용량 확인 | `./srv_monitor/nas_monitor_regular.sh` |

### backup_scripts/ - 백업 자동화

**언제 사용하나요?**
- 데이터 백업이 필요할 때 (별도 cron 권장)

| 스크립트 | 용도 | 실행 예시 |
|----------|------|----------|
| `transfer_data.sh` | rsync 데이터 백업 | `./backup_scripts/transfer_data.sh` |
| `label_studio_export_backup.py` | Label Studio 백업 | `python3 ./backup_scripts/label_studio_export_backup.py` |

```bash
# 백업 cron 예시 (매일 새벽 3시)
0 3 * * * /path/to/backup_scripts/transfer_data.sh
0 3 * * * python3 /path/to/backup_scripts/label_studio_export_backup.py
```

---

## 🐛 문제 해결

### 메일 전송 실패

```bash
sudo systemctl status postfix
echo "Test" | mail -s "Test" admin@company.com
```

### Slack 알림 실패

```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test"}' YOUR_SLACK_WEBHOOK_URL
```

### 디버깅

```bash
export DEBUG_MODE=true
bash -x ./server_monitoring.sh
```

---

## 📊 로그 분석

```bash
# 전체 로그
tail -f log/global_$(date +%F).log

# SSH 보안 로그
tail -f log/ssh_security_$(date +%F).log

# 알림 로그
tail -f log/alerts_$(date +%F).log

# 오류 검색
grep -i "CRIT\|ERROR" log/global_*.log
```

---

## 🔒 보안 주의사항

- `SLACK_WEBHOOK_URL`, `ALERT_EMAIL`은 환경변수로 관리
- 스크립트 권한: `chmod 750 server_monitoring.sh`
- 로그 접근 권한 제한
- `ENABLE_SELF_HEALING=true` 사용시 화이트리스트 검토

---

## ✍️ 버전 정보

- **버전**: v2.0 (2025.06)
- **위치**: `/home/user/arsim/opt_script/server_monitoring.sh`
