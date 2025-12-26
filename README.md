# 🖥️ 통합 서버 모니터링 스크립트

> **Version**: 2025.06  
> **Author**: Server Operations Team  
> **License**: Internal Use Only

## 📋 개요

이 스크립트는 Linux 서버의 종합적인 모니터링을 수행하는 Bash 기반 자동화 도구입니다. 시스템 리소스, 네트워크, 서비스, 컨테이너, SSH 보안 등을 실시간으로 감시하고, 문제 발생 시 관리자에게 즉시 알림을 전송합니다.

## ✨ 주요 기능

### 🔐 **SSH 보안 모니터링**
- **SSH 연결 안정성 감시**: 연결 끊김, 세션 수, CLOSE_WAIT 소켓 감지
- **브루트포스 공격 탐지**: 로그인 실패 시도 분석 및 공격 IP 추적
- **Fail2Ban 연동**: 자동 차단 IP 모니터링 및 반복 공격자 분석
- **SSH 설정 검증**: ClientAliveInterval 등 보안 설정 점검

### 💻 **시스템 리소스 모니터링**
- **디스크 사용량**: 마운트별 용량 및 inode 사용률 감시
- **메모리 감시**: 메모리 사용률 및 스왑 사용량 추적
- **CPU 부하**: Load Average 및 프로세스별 CPU 사용률 분석
- **네트워크 상태**: 연결 상태, 대역폭 사용량, DNS 해상도 테스트

### 🐳 **컨테이너 및 서비스 관리**
- **Docker 모니터링**: 컨테이너 상태, 볼륨 사용량, 로그 분석
- **Kubernetes 지원**: Pod 상태 및 리소스 사용량 감시
- **서비스 상태**: systemd 서비스 자동 재시작 및 상태 추적

### 🚨 **자동 알림 시스템**
- **다중 채널 알림**: 이메일 + Slack 통합 알림
- **중복 방지**: 동일 알림 재전송 방지 로직
- **레벨별 알림**: INFO, WARN, CRIT 단계별 알림 관리
- **시스템 정보 자동 첨부**: 에러 발생시 시스템 상태 정보 자동 포함

### 📊 **로그 관리 및 분석**
- **통합 로깅**: 기능별 로그 파일 자동 생성 및 관리
- **자동 압축**: 오래된 로그 파일 자동 압축 및 아카이빙
- **시스템 이벤트 분석**: kernel panic, OOM, 보안 이벤트 탐지

## 🔧 설치 및 설정

### 전제 조건

```bash
# 필수 패키지 설치 (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y bc mail-utils curl wget

# 필수 패키지 설치 (CentOS/RHEL)
sudo yum install -y bc mailx curl wget
# 또는 (최신 버전)
sudo dnf install -y bc mailx curl wget

# 선택적 패키지 (모니터링 기능 향상)
sudo apt-get install -y lm-sensors ifstat sysstat fail2ban

# Python 패키지 (Label Studio 백업 사용시)
pip install -r requirements.txt
# 또는
pip install label-studio-sdk requests
```

### 스크립트 설치

```bash
# 1. 스크립트 디렉토리 생성
sudo mkdir -p /home/user/arsim/opt_script
cd /home/user/arsim/opt_script

# 2. 스크립트 다운로드 (또는 복사)
sudo wget -O server_monitoring.sh [스크립트_URL]
# 또는
sudo cp server_monitoring.sh /home/user/arsim/opt_script/

# 3. 실행 권한 부여
sudo chmod +x server_monitoring.sh

# 4. 로그 디렉토리 생성
sudo mkdir -p /home/user/arsim/opt_script/log/{archive,run_alerts}
```

### 설정 파일 수정

스크립트는 환경변수로 설정을 오버라이드할 수 있습니다:

```bash
# 서버 식별자 (환경변수로 오버라이드 가능)
HOST_ID="${HOST_ID:-sv3}"

# 알림 설정 (환경변수로 오버라이드 가능)
ALERT_EMAIL="${ALERT_EMAIL:-admin@company.com}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"  # 환경변수 필수

# 경로 설정 (스크립트 위치 기준 자동 설정)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_BASE="${LOG_BASE:-${SCRIPT_DIR}/log}"

# 임계값 (기본값 사용 가능)
SSH_BLOCK_THRESHOLD="${SSH_BLOCK_THRESHOLD:-15}"
SSH_DISCONNECT_THRESHOLD="${SSH_DISCONNECT_THRESHOLD:-20}"
```

### 환경변수 설정 (권장)

```bash
# /etc/environment 또는 ~/.bashrc에 추가
export HOST_ID="production-server-01"
export ALERT_EMAIL="ops@company.com,admin@company.com"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"

# 또는 실행 시 직접 지정
SLACK_WEBHOOK_URL="https://..." ./server_monitoring.sh
```

> ⚠️ **보안 주의**: `SLACK_WEBHOOK_URL`은 스크립트에 직접 기록하지 마세요. 환경변수로 설정하세요.

## 📅 사용법

### 수동 실행

```bash
# 전체 모니터링 실행
sudo ./server_monitoring.sh

# SSH 모니터링만 실행
sudo ./server_monitoring.sh ssh_only

# 요약 보고서만 생성
sudo ./server_monitoring.sh summary_only
```

### 자동 실행 (Crontab)

```bash
# 1. crontab 편집
sudo crontab -e

# 2. 다음 라인 추가 (매 15분마다 실행)
*/15 * * * * /home/user/arsim/opt_script/server_monitoring.sh >> /var/log/monitoring_cron.log 2>&1

# 3. 일일 요약 보고서 (매일 오전 9시)
0 9 * * * /home/user/arsim/opt_script/server_monitoring.sh summary_only
```

### 서비스 등록 (systemd)

```bash
# 1. 서비스 파일 생성
sudo tee /etc/systemd/system/server-monitoring.service << EOF
[Unit]
Description=Server Monitoring Script
After=network.target

[Service]
Type=oneshot
ExecStart=/home/user/arsim/opt_script/server_monitoring.sh
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 2. 타이머 파일 생성 (15분마다 실행)
sudo tee /etc/systemd/system/server-monitoring.timer << EOF
[Unit]
Description=Run Server Monitoring every 15 minutes
Requires=server-monitoring.service

[Timer]
OnCalendar=*:0/15
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 3. 서비스 활성화
sudo systemctl daemon-reload
sudo systemctl enable server-monitoring.timer
sudo systemctl start server-monitoring.timer

# 4. 상태 확인
sudo systemctl status server-monitoring.timer
```

## 📁 디렉토리 구조

```
/home/user/arsim/opt_script/
├── server_monitoring.sh           # 메인 통합 스크립트 (cron 실행용)
├── gpu_inspect.sh                 # GPU 사용 프로세스 추적
├── install_monitoring_suite.sh    # 자동 설치 스크립트
├── README.md                      # 이 파일
│
├── srv_monitor/                   # 개별 모니터링 스크립트 (독립 실행용)
│   ├── disk_monitor_quick.sh      # 빠른 디스크 체크 (가벼움)
│   ├── disk_monitor_detail.sh     # 상세 디스크 분석 (추세 분석)
│   ├── disk_monitor_config.sh     # 디스크 모니터링 설정
│   ├── container_size_check.sh    # Docker 컨테이너 크기 분석
│   ├── docker_prune_check.sh      # 미사용 Docker 이미지/볼륨 확인
│   ├── monitor_iftop.sh           # 네트워크 트래픽 상세 모니터링
│   ├── nas_monitor_regular.sh     # 원격 NAS 디스크 모니터링
│   └── ssmtp.conf                 # 이메일 발송 설정 가이드
│
├── backup_scripts/                # 백업 관련 스크립트
│   ├── transfer_data.sh           # rsync 데이터 백업 전송
│   └── label_studio_export_backup.py  # Label Studio 백업
│
└── log/                           # 로그 디렉토리
    ├── global_YYYY-MM-DD.log      # 전체 로그
    ├── ssh_stability_YYYY-MM-DD.log
    ├── ssh_security_YYYY-MM-DD.log
    ├── system_summary_YYYY-MM-DD.log
    ├── alerts_YYYY-MM-DD.log      # 알림 로그
    ├── archive/                   # 압축된 로그
    │   ├── YYYY-MM-DD_logs.tar.gz
    │   └── alerts_YYYY-MM-DD.tar.gz
    └── run_alerts/                # 실행별 알림 로그
        └── run_alerts_YYYY-MM-DD_HHMMSS.log
```

## 🔧 스크립트 관계 및 사용 시나리오

### server_monitoring.sh vs srv_monitor/ 개별 스크립트

| 구분 | server_monitoring.sh | srv_monitor/ 개별 스크립트 |
|------|---------------------|---------------------------|
| **용도** | cron으로 주기적 통합 실행 | 특정 상황에서 독립 실행 |
| **알림** | 이메일+Slack 통합 | 개별 이메일 알림 |
| **범위** | 모든 체크 한 번에 수행 | 특정 항목만 체크 |
| **무게** | 무거움 (전체 스캔) | 가벼움 (선택적 실행) |

### 사용 시나리오

```bash
# 1. 정기 모니터링 (cron) - 통합 스크립트 사용
*/15 * * * * /opt/scripts/server_monitoring.sh

# 2. 디스크 문제 발생 시 - 빠른 체크
./srv_monitor/disk_monitor_quick.sh

# 3. 디스크 상세 분석 필요 시 - 추세 분석
./srv_monitor/disk_monitor_detail.sh

# 4. Docker 정리 전 확인
./srv_monitor/docker_prune_check.sh

# 5. 컨테이너별 용량 확인
./srv_monitor/container_size_check.sh

# 6. NAS 용량 확인 (원격)
./srv_monitor/nas_monitor_regular.sh
```

## 🚨 알림 시스템

### 알림 레벨

| 레벨 | 설명 | 이메일 | Slack | 시스템 정보 첨부 |
|------|------|--------|-------|------------------|
| **INFO** | 정보성 메시지 | ❌ | ❌ | ❌ |
| **WARN** | 경고 (주의 필요) | ✅* | ✅ | ❌ |
| **CRIT** | 치명적 (즉시 조치 필요) | ✅ | ✅ | ✅ |

*\* WARN 레벨 이메일은 `SEND_WARN_EMAILS=true` 설정시에만 전송*

### 주요 알림 케이스

#### 🔐 **SSH 보안 관련**
- **SSH Brute Force Attempt** (WARN): 임계값 이상의 로그인 실패 시도
- **Fail2Ban Banned IPs** (WARN): 새로운 IP 차단 시
- **SSH Config Issue** (WARN): SSH 설정 문제
- **Frequent SSH Disconnects** (WARN): 과도한 연결 끊김

#### 💻 **시스템 리소스 관련**
- **High System Load** (WARN): CPU 부하 과다
- **Low Memory Warning** (WARN): 메모리 부족
- **Disk Usage Critical** (CRIT): 디스크 사용량 위험 수준

#### 🐳 **서비스 관련**
- **Service Down** (CRIT): 중요 서비스 다운
- **Container Error Spike** (WARN): 컨테이너 에러 급증
- **Script Error** (CRIT): 스크립트 실행 오류

### 알림 예시

```
Subject: -------- !! [WARN][sv3] Server Alert: SSH Brute Force Attempt !! --------

Detected 25 failed SSH login attempts in the past 2 hour ago.

Top new attacking IPs (threshold: 15):
  8  192.168.1.100
  6  10.0.0.50
  4  172.16.0.30

=== System Info ===
Hostname: webserver-01
OS: ubuntu 20.04
Uptime: 5 days, 12:34
Load: 0.45, 0.52, 0.48
Memory: Used: 2048MB (25.6%), Available: 6144MB
```

## 🔧 고급 설정

### 환경별 임계값 조정

```bash
# 컨테이너 환경
if is_container; then
    SSH_DISCONNECT_THRESHOLD=50
    SSH_SESSION_THRESHOLD=100
fi

# 쿠버네티스 노드
if is_kubernetes_node; then
    SSH_DISCONNECT_THRESHOLD=100
    SSH_BLOCK_THRESHOLD=50
fi
```

### 커스텀 모니터링 함수 추가

```bash
# 1. 새로운 모니터링 함수 정의
custom_application_monitor() {
    local log_file="$LOG_BASE/custom_app_$(date +%F).log"
    log "====== custom_application_monitor ======" "$log_file"
    
    # 커스텀 로직 구현
    if ! pgrep -f "my_application" >/dev/null; then
        send_alert "Application Down" "My application is not running" "CRIT" "custom_application_monitor"
    fi
}

# 2. 메인 실행 함수에 추가
run_monitoring() {
    # ... 기존 코드 ...
    safe_run custom_application_monitor
    # ... 나머지 코드 ...
}
```

### 외부 설정 파일 사용

```bash
# /etc/server-monitoring.conf 생성
cat > /etc/server-monitoring.conf << EOF
HOST_ID="production-web-01"
ALERT_EMAIL="ops@company.com"
SSH_BLOCK_THRESHOLD="10"
ENABLE_SELF_HEALING="true"
EOF

# 스크립트에서 설정 파일 로드
if [[ -f /etc/server-monitoring.conf ]]; then
    source /etc/server-monitoring.conf
fi
```

## 🐛 문제 해결

### 자주 발생하는 문제

#### 1. 메일 전송 실패
```bash
# 메일 시스템 확인
sudo systemctl status postfix
sudo tail -f /var/log/mail.log

# 테스트 메일 전송
echo "Test message" | mail -s "Test Subject" admin@company.com
```

#### 2. 권한 문제
```bash
# 스크립트 권한 확인
ls -la /home/user/arsim/opt_script/server_monitoring.sh

# 로그 디렉토리 권한 확인
sudo chown -R root:root /home/user/arsim/opt_script/log
sudo chmod -R 755 /home/user/arsim/opt_script/log
```

#### 3. journalctl 접근 오류
```bash
# systemd-journal 그룹에 사용자 추가
sudo usermod -a -G systemd-journal root

# 또는 전통적인 로그 파일 사용 강제
export FORCE_TRADITIONAL_LOGS=true
```

#### 4. Slack 알림 실패
```bash
# 웹훅 URL 테스트
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message"}' \
  YOUR_SLACK_WEBHOOK_URL

# 네트워크 연결 확인
ping -c 3 hooks.slack.com
```

### 디버깅 모드

```bash
# 디버그 정보 활성화
export DEBUG_MODE=true
bash -x ./server_monitoring.sh

# 특정 함수만 테스트
source ./server_monitoring.sh
monitor_ssh_security
```

## 📊 로그 분석

### 로그 파일 위치 및 내용

```bash
# 전체 실행 로그
tail -f /home/user/arsim/opt_script/log/global_$(date +%F).log

# SSH 보안 로그
tail -f /home/user/arsim/opt_script/log/ssh_security_$(date +%F).log

# 알림 로그
tail -f /home/user/arsim/opt_script/log/alerts_$(date +%F).log

# 실시간 모니터링
watch -n 5 'tail -20 /home/user/arsim/opt_script/log/global_$(date +%F).log'
```

### 로그 검색 예시

```bash
# SSH 공격 분석
grep "Brute Force" /home/user/arsim/opt_script/log/alerts_*.log

# 시스템 오류 검색
grep -i "CRIT\|ERROR" /home/user/arsim/opt_script/log/global_*.log

# 특정 IP 추적
grep "192.168.1.100" /home/user/arsim/opt_script/log/ssh_security_*.log

# 알림 통계
grep -c "send_alert" /home/user/arsim/opt_script/log/global_$(date +%F).log
```

## 🔄 업데이트 및 유지보수

### 스크립트 업데이트

```bash
# 백업 생성
sudo cp server_monitoring.sh server_monitoring.sh.backup.$(date +%F)

# 새 버전 배포
sudo wget -O server_monitoring.sh.new [NEW_VERSION_URL]
sudo chmod +x server_monitoring.sh.new

# 설정 검증 후 교체
sudo ./server_monitoring.sh.new --config-test
sudo mv server_monitoring.sh.new server_monitoring.sh
```

### 정기 유지보수

```bash
# 1. 로그 정리 (30일 이상된 파일 삭제)
find /home/user/arsim/opt_script/log -name "*.log" -mtime +30 -delete

# 2. 압축 아카이브 정리 (90일 이상)
find /home/user/arsim/opt_script/log/archive -name "*.tar.gz" -mtime +90 -delete

# 3. 캐시 파일 정리
rm -f /tmp/ssh_alert_cache.txt /tmp/fail2ban_*.txt

# 4. 설정 검증
./server_monitoring.sh --validate-config
```

## 📈 성능 최적화

### 리소스 사용량 최소화

```bash
# 불필요한 모니터링 비활성화
export SKIP_DOCKER_MONITORING=true
export SKIP_KUBERNETES_MONITORING=true

# 로그 레벨 조정
export LOG_LEVEL=WARN  # INFO 로그 건너뛰기

# 타임아웃 단축
export COMMAND_TIMEOUT=15
export JOURNALCTL_TIMEOUT=10
```

### 대용량 환경 최적화

```bash
# 병렬 처리 활성화
export ENABLE_PARALLEL_MONITORING=true

# 샘플링 모니터링 (매번이 아닌 주기적으로)
export SAMPLE_MONITORING_INTERVAL=3  # 3번 중 1번만 실행
```

## 🔒 보안 고려사항

### 스크립트 보안

```bash
# 1. 파일 권한 제한
sudo chmod 750 server_monitoring.sh
sudo chown root:root server_monitoring.sh

# 2. 로그 파일 권한
sudo chmod 640 /home/user/arsim/opt_script/log/*.log
sudo chown root:adm /home/user/arsim/opt_script/log/*.log

# 3. 중요 정보 마스킹
export MASK_IP_ADDRESSES=true
export MASK_USERNAMES=true
```

### 알림 보안

```bash
# Slack 웹훅 URL 환경 변수로 분리
export SLACK_WEBHOOK_URL_FILE="/etc/monitoring/slack-webhook"
echo "https://hooks.slack.com/services/..." | sudo tee /etc/monitoring/slack-webhook
sudo chmod 600 /etc/monitoring/slack-webhook
```

## 🤝 기여 및 지원

### 버그 리포트

버그 발견시 다음 정보와 함께 리포트해주세요:

1. **OS 정보**: `cat /etc/os-release`
2. **스크립트 버전**: 스크립트 상단 버전 정보
3. **에러 로그**: 관련 로그 파일 내용
4. **재현 단계**: 문제 재현 방법

### 개발 가이드라인

```bash
# 1. 함수명 규칙
function_name()  # 소문자 + 언더스코어

# 2. 변수명 규칙
readonly GLOBAL_CONSTANT="value"  # 전역 상수: 대문자
local local_variable="value"      # 지역 변수: 소문자

# 3. 에러 처리
set -euo pipefail  # 엄격한 에러 처리
validate_number "$input" "default_value"  # 입력 검증

# 4. 로그 규칙
log "→ Success message" "$LOG_FILE"     # 성공
log "⚠️ Warning message" "$LOG_FILE"    # 경고  
log "❌ Error message" "$LOG_FILE"      # 에러
```

---

## 🛡️ Fail2Ban 가이드

### 차단 IP 확인 및 로그
```bash
# 현재 차단된 IP 목록 확인
fail2ban-client status sshd | grep 'Banned IP list'

# 차단 IP 히스토리 로깅
fail2ban-client status sshd | grep 'Banned IP list' >> /var/log/fail2ban_ip_history.log
```

### IP 차단 해제
```bash
sudo fail2ban-client set sshd unbanip <IP주소>
```

### Whitelist (허용 IP) 설정
`/etc/fail2ban/jail.local` 파일에 추가:
```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 7200
ignoreip = 127.0.0.1 192.168.0.0/16 <회사IP대역>
```

```bash
# 화이트리스트 확인
sudo fail2ban-client get sshd ignoreip

# 설정 반영
sudo systemctl restart fail2ban
```

---

## 📂 backup_scripts 폴더

백업 관련 스크립트 (server_monitoring.sh와 별도 수동 관리):

| 파일 | 용도 | 비고 |
|------|------|------|
| `transfer_data.sh` | rsync를 이용한 데이터 백업 전송 | 수동 실행 |
| `label_studio_export_backup.py` | Label Studio 프로젝트 백업 | 수동 실행 또는 별도 cron |

> ⚠️ **주의**: 백업 스크립트는 `server_monitoring.sh`에서 **자동 호출되지 않습니다**.
> 필요시 별도 cron 작업으로 스케줄링하세요.

```bash
# Label Studio 백업 수동 실행
python3 /home/user/arsim/opt_script/backup_scripts/label_studio_export_backup.py

# cron 스케줄링 예시 (매일 새벽 3시)
0 3 * * * python3 /home/user/arsim/opt_script/backup_scripts/label_studio_export_backup.py
```

---
