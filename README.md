# 🖥️ server_monitoring.sh

> 통합 서버 모니터링 & 알림 자동화 스크립트 (2025)
---

## 📌 개요

 스크립트는 Linux 기반  서버의 다양한 자원 상태 및 보안 이벤트에 대해 **주기적인 상태 모니터링, 자동 복구, 자동 Slack/Email 경고 전송, 일일 요약 보고서 생성**을 수행하는 통합 스크립트입니다. 운영 서버의 안정성과 보안 수준을 향상시키기 위해 만들어졌습니다.


**주요 모니터링 항목**
- 시스템 리소스 (CPU, Memory, Disk, Load)
- 프로세스/서비스 상태 및 자동 복구
- Docker 컨테이너 상태 및 로그
- 네트워크/SSH 안정성 및 보안
- 좀비 프로세스/로그 및 발생 알림
- Label Studio 백업 상태
- bash history 자동 백업
- 자동 요약 보고서 생성 및 전송

---

## 📂 구성 개요

- **스크립트 위치**: `/home/user/arsim/opt_script/server_monitoring.sh`
- **로그 저장 위치**: `/home/user/arsim/opt_script/log/`
- **백업 스크립트 위치**: `label_studio_export_backup.py`
- **크론탭 등록 예시**: 아래 참고

---

## 📁 디렉토리 구조

```
/home/user/arsim/opt_script/
│
├── server_monitoring.sh             # 메인 모니터링 스크립트
├── label_studio_export_backup.py   # LabelStudio 백업용 스크립트
├── log/
│   ├── *.log                        # 개별 기능 로그
│   ├── archive/                     # 압축된 오래된 로그
│   └── run_alerts_*.log             # 실행별 경고 요약
```

---

## 🔧 주요 기능

| 카테고리                   | 기능 설명                                           |
| ---------------------- | ----------------------------------------------- |
| **시스템 요약**             | uptime, CPU/메모리/디스크/네트워크 정보, 로그인 사용자 기록         |
| **디스크 감시**             | 사용량 임계치 초과, inode 확인, 급증 감지, 불필요 파일 검토          |
| **도커 볼륨 감시**           | 볼륨별 사용량 점검, 미설치 시 경고 전송                         |
| **네트워크 감시**            | 연결 상태, 대역폭, ping 실패, DNS 해상도 오류 감지              |
| **프로세스 사용량**           | 과도한 자원 사용 프로세스 감지 및 종료 또는 컨테이너 재시작              |
| **I/O 과다 탐지**          | `iotop`, `pidstat`, `vmstat`로 I/O 병목 점검         |
| **서비스 상태 점검**          | nginx, sshd 등 지정 서비스 및 도커 컨테이너 상태 확인            |
| **시스템 온도**             | `lm-sensors` 기반, 임계 온도 초과 시 경고                  |
| **로그 분석**              | journalctl / auth.log 분석 (SSH 실패, OOM, panic 등) |
| **좀비 프로세스**            | 좀비 감지 및 SIGCHLD 처리, 필요 시 컨테이너 재시작               |
| **Label Studio 백업 확인** | 백업 스크립트 실행 후 성공 여부 확인 및 실패 시 알림                 |
| **로그 정리 및 요약**         | 오래된 로그 정리/압축, 일일 Slack/Email 요약 보고서 생성          |
| **SSH/Fail2Ban 감시**    | 로그인 시도/차단 IP 추적, 설정 최적화 추천 포함                   |

---

## 🚨 보안 관련 주의사항

- `SLACK_WEBHOOK_URL`, `ALERT_EMAIL`은 외부 노출되지 않도록 반드시 **.env 또는 secrets 파일에서 관리**하십시오.
- 스크립트는 `root` 권한으로 실행되어야 하므로 실행 파일 권한을 `chmod 700` 등으로 제한하세요.
- 로그 및 히스토리 백업 경로에 민감 정보가 저장될 수 있으니 **외부 접근을 방지**하십시오.
- 스크립트 내에서 임의의 프로세스 종료 또는 컨테이너 재시작을 수행하므로, **화이트리스트 키워드(db, prod 등)**를 주의 깊게 설정하세요.
- `.alert_sent_cache`, `.prev_disk_usage`와 같은 파일에는 이력 정보가 저장되므로 접근권한 제한 또는 주기적 삭제를 권장합니다.

---

## ✅ 사용 방법

### (필요 패키지 설치)

```bash
sudo apt update && sudo apt install -y \
  mailutils curl bc coreutils \
  lm-sensors ifstat iotop sysstat \
  net-tools dnsutils fail2ban
```
- `bc`, `mail`, `docker`, `sensors`, `iotop`, `ifstat`, `pidstat`, `vmstat`, `iostat`, `fail2ban`, `lm-sensors`
> 💡 `iotop`, `ifstat`, `sensors` 등 일부는 선택사항이지만 설치를 권장합니다.

### 일반 실행

```bash
sudo bash server_monitoring.sh
```

### 일일 요약 전용 실행

```bash
sudo bash server_monitoring.sh summary_only
```

### 특정 함수만 실행하고 싶을 때:

```bash
sudo bash -c 'source ./server_monitoring.sh && check_disk_usage'
```

---
## 🔒 보안 및 SSH 감지

- SSH 로그인 실패, 세션 수, 구성수 ClientAlive 등 점검
- Fail2Ban 상태 및 복중 공격자 IP 추적
- 좀비 프로세스 감지 및 커테이너 단위 재시작
- bash history 자동 백업 (`/root`, `/home/*`)

---

## ⏰ 크론탭 설정 예시

```bash
# 매 30분마다 전체 모니터링
*/30 * * * * bash /home/user/arsim/opt_script/server_monitoring.sh >> /home/user/arsim/opt_script/log/cron_monitoring.log 2>&1

# 매일 오전 8시 요약 보고
0 8 * * * bash /home/user/arsim/opt_script/server_monitoring.sh summary_only >> /home/user/arsim/opt_script/log/daily_summary.log 2>&1
```

---

## 📬 알림 구성

- **Slack 알림**: `SLACK_WEBHOOK_URL`로 전송, WARN/CRIT 알림만 발송
- **Email 알림**: `mail` 명령 사용, CRIT은 무조건, WARN은 설정에 따라 전송 (ALERT_EMAIL 필수)

> CRIT 수준은 무조건 전송, WARN 수준은 `SEND_WARN_EMAILS=true` 설정시 전송됩니다.

---

## 📜 관련 로그 파일

| 파일                           | 설명                      |
| ---------------------------- | ----------------------- |
| `global_<date>.log`          | 전체 실행 로그                |
| `run_alerts_<date_time>.log` | 이번 실행 중 발생한 경고/치명 알림 모음 |
| `summary_current_<date>.log` | 최신 일일 요약 보고서            |
| `.alert_sent_cache`          | 알림 중복 방지를 위한 캐시 파일      |
| `.prev_disk_usage`           | 디스크 사용량 비교용 캐시          |

---





---

## 📊 보고서 예시

스크립트는 `/log/summary_current_YYYY-MM-DD.log`에 일일 요약 보고서를 생성합니다.

**Slack 알림 예시**:

```
*Server Summary - server3 (2025-04-21)*
Disk Usage (over 80%):
  /var: 91%
  /home: 82%
Memory: Mem: 62G used of 64G
Load Average: 2.11, 2.09, 2.00
Services:
  docker: active   nginx: active   fail2ban: active
🚨 Recent Alerts:
[CRIT] OOM Killer triggered
[WARN] SSH 로그인 실패 23개
```

---

## 🧠 설정 항목 정보

| 번역 | 설명 | 기본값 |
|--------|------|--------|
| `ENABLE_EMAIL_ALERTS` | 이메일 알림 전송 여부 | true |
| `ENABLE_SLACK_ALERTS` | Slack 전송 여부 | true |
| `SEND_WARN_EMAILS` | WARN 반응 이메일 전송 여부 | true |
| `DISK_WARN`, `DISK_CRIT` | 디스크 사용율 임계치 (%) | 80 / 90 |
| `TEMP_THRESHOLD` | CPU 온도 임계치 (°C) | 80 |
| `ZOMBIE_WARN_THRESHOLD` | 조비 프로세스 경고 기준 | 30 |
| `ENABLE_SELF_HEALING` | 자동 복구 기능 여부 | false |

---

## ✅ 모듈별 기능 요약

| 모듈 | 기능 |
|------|------|
| `collect_system_summary` | 시스템 개요 수집 (uptime, CPU, Mem, Disk 등) |
| `check_disk_usage` | 디스크 및 inode 사용율 확인, 갑적 증가 감지 |
| `check_process_usage` | 고부하 프로세스 탐지 + 자동 종료/재시작 |
| `check_services` | 서비스 상태 점검 + 재시작 시도 |
| `analyze_system_logs` | 시스템 로그 (journalctl, auth.log) 분석 |
| `check_io_heavy_processes` | iotop/pidstat 기능 I/O 가능 탐지 |
| `manage_zombie_processes` | 조비 프로세스 자동 감지 및 정리 |
| `check_network_status` | ping, ifstat, DNS 상태 점검 |
| `check_system_temperature` | lm-sensors 기능 온돐 확인 |
| `monitor_ssh_stability` | 세션 수, CLOSE_WAIT, SSH 설정 안정성 점검 |
| `monitor_ssh_security` | 로그인 실패 / fail2ban 상태 확인 |
| `analyze_container_logs` | 도커 커테이너 에러 및 재시작 비도 감지 |
| `backup_bash_history` | root, 사용자 bash history 백업 |
| `clean_old_logs` | 오래된 로그 압축 및 삭제 |
| `generate_summary` | 일일 보고서 생성 및 알림 전송 |

---

## 📌 참고

- 스크립트는 루트 권한으로 실행되어야 합니다.
- 대부분의 모듈은 실행 시 오류시 자동 복구 또는 알림만 수행하며, 시스템 자체를 변경하지 않습니다.
- 자가 복구 기능 (`ENABLE_SELF_HEALING=true`) 활성화 시에는 주의해서 사용해야 합니다.

---

## 📌 유지관리 체크리스트

- [ ] `.env` 또는 secrets 분리 적용 여부 확인
- [ ] 로그 및 백업 파일 접근 권한 제한 적용 여부
- [ ] `ENABLE_SELF_HEALING=true` 설정 시 대상 화이트리스트 검토
- [ ] 알림 캐시 파일(`.alert_sent_cache`) 주기적 삭제 스케줄 확인

---


## ✍️ 작성자 및 버전

- 작성자: [areum sim](mailto:sar10320@gmail.com)
- 버전: `v1.5` (2025.04.21)
- 위치: `/home/user/arsim/opt_script/server_monitoring.sh`

---

