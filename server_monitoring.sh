#!/bin/bash
# server_monitoring.sh
# -------------------------------------------------------------------
# 통합 서버 모니터링 스크립트 모음 (2025.03)
# 시스템 리소스, 네트워크,  서비스, 도커, 프로세스, 로그 등을 주기적으로 모니터링 / 관리자에게 경고 메일 전송
#
# [시스템 요약]
#   - 시스템 정보, uptime, CPU/메모리 사용량, 디스크, 네트워크,로그인 사용자 등을 로그에 기록.
#   - 서버 재부팅 후 uptime이 10분 미만이면 경고.
#
# [디스크 사용량 체크]
#   - 각 마운트 지점의 사용량과 inode 사용량을 확인.
#   - 경고 임계치(예: 80%) 및 치명 임계치(예: 90%) 초과 시 각각 경고/치명 알림.
#   - 10GB 이상의 큰 파일 목록을 기록해 불필요한 파일 제거 시 참고.
#
# [도커 볼륨 감시]
#   - 도커가 설치되어 있다면, 각 볼륨의 사용량을 점검하고 로그 기록.
#
# [네트워크 상태 체크]
#   - 현재 네트워크 연결 상태와 통계를 기록.
#   - ifstat로 대역폭 사용량을 측정 (ifstat가 설치되어 있을 경우).
#   - 지정한 대상(IP)에 대한 핑 테스트를 실시, 실패 시 경고.
#   - DNS 해상도 테스트 실패 시 경고.
#
# [프로세스 리소스 과다 체크]
#   - CPU나 메모리 사용량이 지정 임계치를 초과하는 프로세스를 확인.
#   - 해당 프로세스가 도커 컨테이너에 속하면:
#         * 컨테이너 이름에 중요한 키워드(예: db, prod 등)가 없을 경우, 컨테이너를 재시작.
#         * 중요 컨테이너인 경우 수동 점검 필요하다는 치명 알람.
#   - 일반 프로세스인 경우:
#         * 웹서버, 데이터베이스 등 중요 프로세스가 아니라면 SIGTERM을 보내고, 종료되지 않으면 SIGKILL을 발송하여 강제 종료.
#
# [I/O 과다 탐지]
#   - iotop을 이용하여 I/O 사용량이 많은 프로세스를 기록.
#   - iotop이 없는 경우 WARN 메일을 발송.
#
# [서비스 상태 체크]
#   - 설정된 서비스들이 정상적으로 실행 중인지 확인.
#   - 서비스가 다운되어 있으면 재시작을 시도하고, 재시작 실패 시 치명 알람.
#   - 도커 컨테이너 상태도 점검, 중지된 컨테이너가 있으면 경고.
#
# [시스템 온도 모니터링]
#   - lm-sensors를 이용해 시스템 온도를 체크하고, 온도가 80°C 이상이면 경고 메일 발송.
#
# [시스템 로그 분석]
#   - journalctl 및 /var/log/auth.log를 분석하여 심각한 에러,
#     SSH 로그인 실패, OOM 이벤트 등 이상 상황을 확인 후 경고.
#
# [좀비 프로세스 감시]
#   - 좀비 프로세스 수가 10개 이상이면 경고 메일 발송.
#   - 좀비 프로세스와 해당 부모 프로세스 정보를 기록하고, 부모 프로세스에 SIGCHLD 신호를 보내 정리 시도.
#
# [백업 상태 확인]
#   - Label Studio 백업 스크립트를 실행하여 성공 여부를 체크.
#   - 실패 시 치명 알람을 발송.
#
# [로그 정리 및 요약]
#   - 오래된 로그 파일을 삭제하거나 압축하여 저장 공간을 확보.
#   - 일일 요약을 이메일로 전송해 전반적인 상태를 보고.

# -------------------------------------------------------------------

# 기본 설정 - 스크립트 오류 처리
export PATH=$PATH:/sbin:/usr/sbin
set -euo pipefail
IFS=$'\n\t'
# set -e: 명령어 실패 시 즉시 종료
# set -u: 정의되지 않은 변수 사용 시 에러
# set -o pipefail: 파이프라인 중 하나라도 실패하면 전체 실패
# IFS: 단어 분리를 개행과 탭으로 제한

# 루트 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "이 스크립트는 루트 권한으로 실행해야 합니다."
    exit 1
fi

# [서버 식별자 설정]
HOST_ID="${HOST_ID:-sv3}"  # 환경변수로 오버라이드 가능

#######################################################################
### [1. 기본 경로 설정] ###############################################
#######################################################################
# 스크립트 위치 기준 경로 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 로그 디렉토리 설정 (환경변수로 오버라이드 가능)
LOG_BASE="${LOG_BASE:-${SCRIPT_DIR}/log}"
LOG_ARCHIVE_DIR="${LOG_BASE}/archive"
LOG_ALERTS_DIR="${LOG_BASE}/run_alerts"

# 로그 파일 경로
GLOBAL_LOG="$LOG_BASE/global_$(date +%F).log"
RUN_ALERTS_FILE="${LOG_ALERTS_DIR}/run_alerts_$(date +%F_%H%M%S).log"

# 기타 경로 설정 (환경변수로 오버라이드 가능)
LABEL_STUDIO_BACKUP_SCRIPT="${LABEL_STUDIO_BACKUP_SCRIPT:-${SCRIPT_DIR}/label_studio_export_backup.py}"

# 디렉토리 생성
mkdir -p "$LOG_BASE" "$LOG_ARCHIVE_DIR" "$LOG_ALERTS_DIR"
: > "$RUN_ALERTS_FILE"  # 알림 로그 파일 초기화

#######################################################################
### [2. 환경변수 기본값 설정] #########################################
#######################################################################
# SSH 모니터링 설정
export SSH_FAIL_TIME_RANGE="${SSH_FAIL_TIME_RANGE:-2 hour ago}"
export SSH_FAIL_WARN_COUNT="${SSH_FAIL_WARN_COUNT:-10}"
export SSH_BLOCK_THRESHOLD="${SSH_BLOCK_THRESHOLD:-15}"
export SSH_DISCONNECT_THRESHOLD="${SSH_DISCONNECT_THRESHOLD:-20}"
export SSH_SESSION_THRESHOLD="${SSH_SESSION_THRESHOLD:-50}"
export CLOSE_WAIT_THRESHOLD="${CLOSE_WAIT_THRESHOLD:-100}"
export SSH_RECOMMENDED_INTERVAL="${SSH_RECOMMENDED_INTERVAL:-30}"
export SSH_MAX_INTERVAL="${SSH_MAX_INTERVAL:-120}"
export F2B_BANTIME="${F2B_BANTIME:-600}"
# 임계값 설정
DISK_WARN=80           # 디스크 사용량 경고 임계치 (%)
DISK_CRIT=90           # 디스크 사용량 치명 임계치 (%)
DISK_INCREASE_THRESHOLD_GB=50  # 디스크 사용량 급격한 증가 감지를 위한 임계값 (GB 단위)

CPU_WARN_PERCENT=75    # CPU 사용량 경고 (%)
MEM_WARN_PERCENT=85    # 메모리 사용량 경고 (%)

IO_WARN_THRESHOLD=30   # I/O 읽기+쓰기가 30% 이상인 프로세스 경고
IO_CRIT_THRESHOLD=50   # I/O 읽기+쓰기가 50% 이상인 프로세스 위험 알림

ZOMBIE_WARN_THRESHOLD=30    # 좀비 프로세스 경고 임계치
ZOMBIE_KILL_THRESHOLD=50    # 좀비 프로세스 강제 종료 임계치

LOAD_WARN_THRESHOLD=200  # Load Average가 이 값 초과하면 경고 ((= 128 CPU × 1.5 / 2배면 부하))

TEMP_THRESHOLD=80      # 온도 경고 임계치 (°C)

# 로그 관리 설정
RETENTION_DAYS=30      # 로그 보관 기간 (일)
COMPRESS_DELAY=7       # N일 이상 지난 로그 파일을 압축
SIZE_THRESHOLD_KB=5242880  # 로그 디렉토리 용량 경고 임계치 (5GB in KB)

# 모니터링 대상 설정
SERVICES=("sshd" "docker" "nginx" "fail2ban")
PING_TARGETS=("8.8.8.8" "1.1.1.1")

# ==== [NEW] 커널/워치독/락업 대응 ENV ====
export WATCHDOG_ENSURE="${WATCHDOG_ENSURE:-true}"          # 커널 watchdog/sysrq 보증
export SOFTLOCKUP_ALERT="${SOFTLOCKUP_ALERT:-true}"        # soft lockup/hung task 감지 알림

# 컨테이너 과부하 차단 대상 (Cursor/IDE 컨테이너 이름)
export TARGET_CONTAINER="${TARGET_CONTAINER:-cursor_container}"

# 과부하/폭주 임계치
export RG_PROC_THRESHOLD="${RG_PROC_THRESHOLD:-120}"       # rg 프로세스 N개 이상이면 차단
export LOAD_CUTOFF="${LOAD_CUTOFF:-120}"                   # 1분 loadavg가 이 값 초과 시 차단
export ZOMBIE_CUTOFF="${ZOMBIE_CUTOFF:-20}"                # 좀비 프로세스 수 임계

# SSH 보조 포트 (메인 포트 이상시 대체)
export SSH_FALLBACK_PORT="${SSH_FALLBACK_PORT:-2222}"

# 커널 런타임 보증값 (영구값은 /etc/sysctl.d/99-watchdog.conf 로 이미 구성됨)
export WD_THRESH_RUNTIME="${WD_THRESH_RUNTIME:-10}"
export HUNG_TASK_SECS_RUNTIME="${HUNG_TASK_SECS_RUNTIME:-120}"

# 상태 기록 경로(락업 탐지 시 ‘이전 실행 이후’만 스캔)
export STATE_DIR="${STATE_DIR:-$LOG_BASE/.state}"
mkdir -p "$STATE_DIR"


#######################################################################
### [3. 알림 설정] ####################################################
#######################################################################
# 알림 활성화 설정 (환경변수로 오버라이드 가능)
ENABLE_EMAIL_ALERTS="${ENABLE_EMAIL_ALERTS:-true}"
ENABLE_SLACK_ALERTS="${ENABLE_SLACK_ALERTS:-true}"
SEND_WARN_EMAILS="${SEND_WARN_EMAILS:-true}"     # WARN 레벨도 이메일로 받기

# 알림 대상 설정 (환경변수로 오버라이드 가능)
# 보안: 민감한 정보는 환경변수로 설정하세요
ALERT_EMAIL="${ALERT_EMAIL:-areum_sim@kolon.com,yeongsin_byeon@kolon.com}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"  # 환경변수로 설정 필요

# 서버 자가 복구 기능 활성화 여부 (위험할 수 있으므로 기본은 false)
ENABLE_SELF_HEALING="${ENABLE_SELF_HEALING:-false}"


#######################################################################
### [5. 유틸리티 함수들] ###############################################
#######################################################################
# 필수 및 선택적 명령어 정의
REQUIRED_COMMANDS=("bc" "mail")
OPTIONAL_COMMANDS=("docker" "sensors" "ifstat" "pidstat" "iostat" "vmstat") # "iotop" 

# 의존성 확인 결과 로깅을 위한 임시 함수
log_dependency() {
    local msg="$1"
    local level="$2"  # INFO, WARN, CRIT
    echo "[$(date '+%F %T')] [$level] $msg" >> "$GLOBAL_LOG"
    echo "[$level] $msg"  # 터미널에도 출력
}

# 필수 명령어 확인
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_dependency "필수 명령어 $cmd가 설치되어 있지 않습니다. 계속 진행할 수 없습니다." "CRIT"
        exit 1
    fi
done

# 선택적 명령어 확인
MISSING_COMMANDS=""
for cmd in "${OPTIONAL_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_dependency "$cmd 명령어를 찾을 수 없습니다. 일부 기능이 제한될 수 있습니다." "WARN"
        MISSING_COMMANDS="${MISSING_COMMANDS} $cmd"
    fi
done


# === [NEW] Red Hat 대응 포함 의존성 체크 ===
check_dependencies() {
    local LOG_FILE="$LOG_BASE/dependency_check_$(date +%F).log"
    log "====== check_dependencies ======" "$LOG_FILE"

    local missing=()
    for cmd in fail2ban-client mail bc docker sensors; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        local msg="The following commands are missing: ${missing[*]}\n"
        msg+="\nRed Hat/CentOS 계열에서는 다음 명령으로 설치하세요:\n"
        msg+="yum install -y epel-release ${missing[*]}"
        send_alert "Missing Tools on RedHat" "$msg" "WARN" "check_dependencies ($LOG_FILE)"
    fi
} 


# ==== [NEW] 커널 watchdog/sysrq 런타임 보증 (idempotent) ====
ensure_kernel_watchdog_baseline() {
    local LOG_FILE="$LOG_BASE/watchdog_$(date +%F).log"
    log "====== ensure_kernel_watchdog_baseline ======" "$LOG_FILE"
    [[ "$WATCHDOG_ENSURE" != "true" ]] && { log "SKIP watchdog ensure" "$LOG_FILE"; return 0; }

    # 즉시 런타임 반영 (재부팅 전까지 유효)
    sysctl -w kernel.watchdog=1              >/dev/null 2>&1 || true
    sysctl -w kernel.watchdog_thresh="$WD_THRESH_RUNTIME"   >/dev/null 2>&1 || true
    sysctl -w kernel.hung_task_timeout_secs="$HUNG_TASK_SECS_RUNTIME" >/dev/null 2>&1 || true
    sysctl -w kernel.sysrq=1                 >/dev/null 2>&1 || true

    # 결과 로깅
    sysctl -a | grep -E "watchdog|hung_task_timeout_secs|sysrq" >>"$LOG_FILE" 2>/dev/null || true
    log "watchdog/sysrq baseline ensured (runtime)" "$LOG_FILE"
}

# ==== [NEW] soft lockup / hung task / blocked task 탐지 (이전 실행 이후) ====
check_softlockup_and_hung_tasks() {
    local LOG_FILE="$LOG_BASE/softlockup_scan_$(date +%F).log"
    log "====== check_softlockup_and_hung_tasks ======" "$LOG_FILE"
    [[ "$SOFTLOCKUP_ALERT" != "true" ]] && { log "SKIP softlockup scan" "$LOG_FILE"; return 0; }

    local SINCE_FILE="$STATE_DIR/softlockup_since"
    local SINCE_OPT="--since '1 hour ago'"
    if [[ -f "$SINCE_FILE" ]]; then
        SINCE_OPT="--since \"$(cat "$SINCE_FILE")\""
    fi
    date -Is >"$SINCE_FILE"

    # journald 기반 커널 로그 스캔
    # shellcheck disable=SC2086
    local out
    out=$(bash -lc "journalctl -k $SINCE_OPT --no-pager | egrep -i 'soft lockup|hung task|blocked for more than|rcu_sched self-detected stall' || true")

    if [[ -n "$out" ]]; then
        echo "$out" >>"$LOG_FILE"
        send_alert "Kernel soft lockup/hung task detected" \
            "Kernel anomalies since last run:\n$(echo "$out" | tail -n 60)" \
            "WARN" "check_softlockup_and_hung_tasks ($LOG_FILE)"
    else
        log "No kernel lockup/hung patterns since last run" "$LOG_FILE"
    fi
}

# ==== [NEW] 과부하/좀비/rg 폭주 시 컨테이너 안전 중단 ====
check_overload_and_stop_container() {
    local LOG_FILE="$LOG_BASE/overload_guard_$(date +%F).log"
    log "====== check_overload_and_stop_container ======" "$LOG_FILE"

    # 1분 loadavg
    local load1=$(awk '{print $1}' /proc/loadavg)
    local load1_int=${load1%.*}

    # 좀비 수
    local zombies
    zombies=$(ps axo stat | awk '$1 ~ /Z/ {c++} END{print c+0}')

    # rg 프로세스 폭주 수
    local rgcount
    rgcount=$(pgrep -c rg || echo 0)

    log "load1=${load1}, zombies=${zombies}, rg=${rgcount}" "$LOG_FILE"

    if (( load1_int > LOAD_CUTOFF )) || (( zombies > ZOMBIE_CUTOFF )) || (( rgcount > RG_PROC_THRESHOLD )); then
        log "THRESHOLD EXCEEDED → try graceful stop container: ${TARGET_CONTAINER}" "$LOG_FILE"

        if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "${TARGET_CONTAINER}"; then
            # 우선 정상 종료 시도
            docker stop "${TARGET_CONTAINER}" --time=10 >>"$LOG_FILE" 2>&1 || true
            sleep 3
            # 아직 살아있으면 kill(최소화)
            if docker ps --format '{{.Names}}' | grep -qx "${TARGET_CONTAINER}"; then
                docker kill "${TARGET_CONTAINER}" >>"$LOG_FILE" 2>&1 || true
            fi
            send_alert "Container stopped by overload guard" \
                "Stopped ${TARGET_CONTAINER}\nload1=${load1}, zombies=${zombies}, rg=${rgcount}" \
                "WARN" "check_overload_and_stop_container ($LOG_FILE)"
        else
            log "docker not available or container not running" "$LOG_FILE"
        fi
    fi
}

# ==== [NEW] SSH 보조 포트 확보 (2222) ====
check_and_recover_ssh_fallback() {
    local LOG_FILE="$LOG_BASE/ssh_fallback_$(date +%F).log"
    log "====== check_and_recover_ssh_fallback ======" "$LOG_FILE"

    # 메인 22 포트 리스닝 체크
    if ! ss -ltn 2>/dev/null | grep -q ":22 "; then
        log "sshd:22 not listening → restarting ssh" "$LOG_FILE"
        systemctl restart ssh 2>>"$LOG_FILE" || systemctl restart sshd 2>>"$LOG_FILE" || true
    fi

    # 보조 포트 리스닝 없으면 임시 인스턴스 기동
    if ! ss -ltn 2>/dev/null | grep -q ":${SSH_FALLBACK_PORT} "; then
        log "ssh fallback port ${SSH_FALLBACK_PORT} not active → starting ad-hoc instance" "$LOG_FILE"
        # ad-hoc sshd (현재 설정 파일 사용, 포트만 오버라이드 / PAM 비활성)
        /usr/sbin/sshd -o Port="${SSH_FALLBACK_PORT}" -o UsePAM=no -o PasswordAuthentication=no -o PubkeyAuthentication=yes >>"$LOG_FILE" 2>&1 || true
        sleep 1
        if ss -ltn 2>/dev/null | grep -q ":${SSH_FALLBACK_PORT} "; then
            send_alert "SSH fallback activated" "Listening on port ${SSH_FALLBACK_PORT}" "INFO" "check_and_recover_ssh_fallback ($LOG_FILE)"
        fi
    fi
}

# ==== [NEW] ripgrep 제한 안내(컨테이너 이미지/EntryPoint에서 적용 권장) ====
notify_rg_hardening_needed() {
    local LOG_FILE="$LOG_BASE/rg_notice_$(date +%F).log"
    log "====== notify_rg_hardening_needed ======" "$LOG_FILE"
    if [[ ! -f "/root/.ripgreprc" ]]; then
        log "Host /root/.ripgreprc not found (ok if managed inside container). Recommended:" "$LOG_FILE"
        log "  --max-filesize 5M; ignore node_modules, .git, dist, media" "$LOG_FILE"
    fi
}


# =============================================================================
# 시스템 감지 및 유틸리티 함수들
# =============================================================================

# 운영체제 감지 (ubuntu, centos, rhel 등)
detect_os() {
    local os_id=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        os_id="$ID"
    elif [[ -f /etc/redhat-release ]]; then
        if grep -qi "centos" /etc/redhat-release; then
            os_id="centos"
        elif grep -qi "red hat\|rhel" /etc/redhat-release; then
            os_id="rhel"
        else
            os_id="redhat"
        fi
    elif [[ -f /etc/debian_version ]]; then
        os_id="debian"
    elif [[ -f /etc/alpine-release ]]; then
        os_id="alpine"
    else
        # fallback to uname
        os_id=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    
    echo "$os_id"
}

# 운영체제 버전 감지
detect_os_version() {
    local version=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        version="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        version=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        version=$(cat /etc/debian_version)
    fi
    
    echo "$version"
}

# 쿠버네티스 노드 여부 판단 (개선됨)
is_kubernetes_node() {
    # 다양한 k8s 환경 감지
    if [[ -d "/var/run/secrets/kubernetes.io" ]] || \
       [[ -f "/etc/kubernetes/kubelet.conf" ]] || \
       [[ -f "/var/lib/kubelet/config.yaml" ]] || \
       pgrep -f "kubelet" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 컨테이너 환경 감지
is_container() {
    # Docker 컨테이너 감지
    if [[ -f /.dockerenv ]] || \
       grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
        echo "docker"
        return 0
    fi
    
    # Podman 감지
    if [[ -n "${container:-}" ]] && [[ "$container" == "podman" ]]; then
        echo "podman"
        return 0
    fi
    
    # LXC/LXD 감지
    if [[ -f /proc/1/environ ]] && grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        echo "lxc"
        return 0
    fi
    
    return 1
}

# systemd 사용 여부 확인
is_systemd() {
    if command -v systemctl >/dev/null 2>&1 && \
       systemctl is-system-running >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 인증 로그 파일 경로 자동 탐색 (개선됨)
detect_auth_log_file() {
    local os_type
    os_type=$(detect_os)
    
    case "$os_type" in
        "ubuntu"|"debian")
            local files=("/var/log/auth.log" "/var/log/syslog" "/var/log/messages")
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            local files=("/var/log/secure" "/var/log/messages" "/var/log/auth.log")
            ;;
        "alpine")
            local files=("/var/log/messages" "/var/log/auth.log")
            ;;
        *)
            local files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/syslog")
            ;;
    esac
    
    for f in "${files[@]}"; do
        if [[ -f "$f" && -r "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    
    # 로그 파일을 찾지 못한 경우
    echo ""
    return 1
}

# SSH 설정 파일 경로 감지
detect_ssh_config() {
    local configs=("/etc/ssh/sshd_config" "/etc/sshd_config" "/usr/local/etc/ssh/sshd_config")
    
    for config in "${configs[@]}"; do
        if [[ -f "$config" && -r "$config" ]]; then
            echo "$config"
            return 0
        fi
    done
    
    echo ""
    return 1
}

# fail2ban jail 이름 감지
detect_fail2ban_ssh_jail() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo ""
        return 1
    fi
    
    local jails=("sshd" "ssh" "ssh-iptables" "ssh-ddos" "openssh")
    local jail_list
    
    # 활성 jail 목록 가져오기
    if jail_list=$(timeout 10s fail2ban-client status 2>/dev/null); then
        for jail in "${jails[@]}"; do
            if echo "$jail_list" | grep -q "$jail"; then
                echo "$jail"
                return 0
            fi
        done
    fi
    
    echo ""
    return 1
}

# 네트워크 상태 확인 명령어 감지
detect_network_cmd() {
    if command -v ss >/dev/null 2>&1; then
        echo "ss"
    elif command -v netstat >/dev/null 2>&1; then
        echo "netstat"
    else
        echo ""
        return 1
    fi
}

# 로그 관리 시스템 감지
detect_log_system() {
    if is_systemd && command -v journalctl >/dev/null 2>&1; then
        echo "journald"
    elif [[ -d "/var/log" ]]; then
        echo "syslog"
    else
        echo "unknown"
        return 1
    fi
}

# 시스템 정보 요약 출력
print_system_info() {
    local log_file="${1:-/dev/stdout}"
    
    {
        echo "=== System Information ==="
        echo "OS: $(detect_os) $(detect_os_version)"
        echo "Container: $(is_container 2>/dev/null && echo "Yes ($(is_container))" || echo "No")"
        echo "Kubernetes Node: $(is_kubernetes_node && echo "Yes" || echo "No")"
        echo "Init System: $(is_systemd && echo "systemd" || echo "sysvinit/other")"
        echo "Log System: $(detect_log_system)"
        echo "Auth Log: $(detect_auth_log_file || echo "Not found")"
        echo "SSH Config: $(detect_ssh_config || echo "Not found")"
        echo "Fail2Ban SSH Jail: $(detect_fail2ban_ssh_jail || echo "Not found/inactive")"
        echo "Network Command: $(detect_network_cmd || echo "Not available")"
        echo "=========================="
    } >> "$log_file"
}

# 환경별 SSH 모니터링 설정 조정
configure_ssh_monitoring_for_env() {
    local os_type
    os_type=$(detect_os)
    
    # 컨테이너 환경에서는 모니터링 조정
    if is_container >/dev/null 2>&1; then
        export SSH_DISCONNECT_THRESHOLD=50  # 컨테이너에서는 더 관대하게
        export SSH_SESSION_THRESHOLD=100
        export CLOSE_WAIT_THRESHOLD=200
    fi
    
    # 쿠버네티스 노드에서는 더 관대한 설정
    if is_kubernetes_node; then
        export SSH_DISCONNECT_THRESHOLD=100
        export SSH_SESSION_THRESHOLD=200
        export SSH_FAIL_WARN_COUNT=10
        export SSH_BLOCK_THRESHOLD=50
    fi
    
    # OS별 특정 설정
    case "$os_type" in
        "alpine")
            # Alpine에서는 일부 명령어가 다를 수 있음
            export SSH_RECOMMENDED_INTERVAL=60
            export SSH_MAX_INTERVAL=300
            ;;
        "centos"|"rhel")
            # CentOS/RHEL에서는 SELinux 고려
            export SSH_RECOMMENDED_INTERVAL=30
            ;;
    esac
}

# 의존성 체크 및 경고
check_monitoring_dependencies() {
    local log_file="${1:-/dev/stdout}"
    local missing_deps=()
    
    # 필수 명령어들 체크
    local required_cmds=("grep" "awk" "wc" "sort" "uniq")
    local optional_cmds=("ss" "netstat" "journalctl" "fail2ban-client")
    
    echo "=== Dependency Check ===" >> "$log_file"
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
            echo "❌ Missing required command: $cmd" >> "$log_file"
        fi
    done
    
    for cmd in "${optional_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "⚠️  Optional command not found: $cmd" >> "$log_file"
        else
            echo "✅ Available: $cmd" >> "$log_file"
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "❌ Missing required dependencies: ${missing_deps[*]}" >> "$log_file"
        return 1
    else
        echo "✅ All required dependencies found" >> "$log_file"
        return 0
    fi
}

### [5. 핵심 함수들] ##################################################
# log(): 메시지(로그)를 함수 개별 파일과 전체 로그 파일에 동시에 기록
log() {
    local msg="$1"
    local file="$2"
    local log_entry="[$(date '+%F %T')] $msg"
    echo -e "$log_entry" >> "$file"
    
    # 메시지가 WARN/CRIT 또는 제목(=== , ---) 패턴으로 시작하면 글로벌 로그에 기록
    if echo "$msg" | grep -qE "\[(WARN|CRIT)\]|^(===|---)"; then
        echo -e "$log_entry" >> "$GLOBAL_LOG" # 전체 로그 파일에 기록
    fi
}

# run_cmd: 개별 명령 실행 후 실패 시 로그와 알림 전송
# 실행 형태 : run_cmd "$LOG_FILE" <command>
run_cmd() {
    local LOG_FILE="$1"
    shift
    local cmd_name="$1"
    shift
    local resolved_cmd
    
    # 명령어 경로 해결
    resolved_cmd=$(command -v "$cmd_name" 2>/dev/null || true)
    if [[ -z "$resolved_cmd" && -x "/sbin/$cmd_name" ]]; then
        resolved_cmd="/sbin/$cmd_name"
    elif [[ -z "$resolved_cmd" && -x "/usr/sbin/$cmd_name" ]]; then
        resolved_cmd="/usr/sbin/$cmd_name"
    fi
    
    # 명령어가 없을 경우
    if [[ -z "$resolved_cmd" ]]; then
        log "❌ Command not found: $cmd_name" "$LOG_FILE"
        send_alert "Command Not Found" "Command: $cmd_name" "ERROR" "run_cmd"
        return 127  # 127 = 명령어를 찾을 수 없음
    fi
    
    # 명령어 실행
    local timeout_secs=30
    local cmd_str="$resolved_cmd $(printf '%q ' "$@")"
    local output
    output=$(timeout "$timeout_secs" "$resolved_cmd" "$@" 2>&1)
    local exit_code=$?
    
    # 출력 정리 및 로깅
    clean_output=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')  # ANSI 색상코드 제거
    echo -e ">>> CMD: $cmd_str\n$clean_output" >> "$LOG_FILE"

    # 오류 코드 평가 (자세한 설명 추가)
    case $exit_code in
        0)
            log "✅ Command success: $cmd_str" "$LOG_FILE"
            ;;
        1)
            # Exit code 1은 일반적인 오류이지만, grep 명령어의 경우 "일치 항목 없음"을 의미함
            if echo "$cmd_name" | grep -qE 'grep|egrep|fgrep'; then
                log "✅ No match found for command: $cmd_str (exit 1 - No matches found)" "$LOG_FILE"
                return 0  # grep에서의 "일치 항목 없음"은 정상으로 처리
            else
                log "❌ Command failed with general error: $cmd_str (exit 1 - Operation failed)" "$LOG_FILE"
                send_alert "Command Failed" "Command: $cmd_str\nExit code: 1 (Operation failed)\nOutput:\n$output" "WARN" "run_cmd"
            fi
            ;;
        2)
            # Exit code 2는 일반적으로 명령줄 구문 오류 또는 파일 접근 문제
            log "❌ Command failed: $cmd_str (exit 2 - Syntax error or file not accessible)" "$LOG_FILE"
            if [[ "$output" == *"No such file or directory"* ]]; then
                send_alert "File Not Found" "Command: $cmd_str\nExit code: 2\nOutput: File not found or not accessible" "INFO" "run_cmd"
            else
                send_alert "Command Failed" "Command: $cmd_str\nExit code: 2 (Syntax error or file not accessible)\nOutput:\n$output" "WARN" "run_cmd"
            fi
            ;;
        3)
            # Exit code 3은 systemctl에서 서비스가 inactive 상태임을 의미할 수 있음
            if [[ "$cmd_name" == *"systemctl"* && "$*" == *"is-active"* ]]; then
                log "⚠️ Service is not active: $cmd_str (exit 3 - Service inactive)" "$LOG_FILE"
                send_alert "Service Inactive" "Service checked with: $cmd_str is inactive\nExit code: 3" "INFO" "run_cmd"
            else
                log "❌ Command failed: $cmd_str (exit 3)" "$LOG_FILE"
                send_alert "Command Failed" "Command: $cmd_str\nExit code: 3\nOutput:\n$output" "WARN" "run_cmd"
            fi
            ;;
        124)
            # Exit code 124는 timeout 명령에 의한 시간 초과
            log "❌ Command timed out: $cmd_str (exit 124 - Command execution timed out)" "$LOG_FILE"
            send_alert "Command Timeout" "Command: $cmd_str\nExit code: 124 (Timed out after $timeout_secs seconds)" "WARN" "run_cmd"
            ;;
        126)
            # Exit code 126은 명령이 존재하지만 실행 권한이 없음
            log "❌ Command not executable: $cmd_str (exit 126 - Permission denied)" "$LOG_FILE"
            send_alert "Command Not Executable" "Command: $cmd_str\nExit code: 126 (Permission denied)" "ERROR" "run_cmd"
            ;;
        127)
            # Exit code 127은 명령을 찾을 수 없음
            log "❌ Command not found: $cmd_str (exit 127 - Command not found)" "$LOG_FILE"
            send_alert "Command Not Found" "Command: $cmd_str\nExit code: 127 (Command not found)" "ERROR" "run_cmd"
            ;;
        130)
            # Exit code 130은 사용자에 의한 중단 (Ctrl+C)
            log "⚠️ Command interrupted: $cmd_str (exit 130 - Interrupted by user)" "$LOG_FILE"
            send_alert "Command Interrupted" "Command: $cmd_str\nExit code: 130 (Interrupted by user or signal)" "INFO" "run_cmd"
            ;;
        137)
            # Exit code 137은 SIGKILL에 의한 강제 종료 (OOM Killer에 의한 종료일 수 있음)
            log "❌ Command killed: $cmd_str (exit 137 - Process killed, possibly by OOM Killer)" "$LOG_FILE"
            send_alert "Command Killed" "Command: $cmd_str\nExit code: 137 (Process killed, possibly by Out of Memory Killer)" "WARN" "run_cmd"
            ;;
        *)
            # 기타 오류 코드
            log "❌ Command failed: $cmd_str (exit $exit_code - Unknown error code)" "$LOG_FILE"
            send_alert "Command Failed" "Command: $cmd_str\nExit code: $exit_code\nOutput:\n$output" "WARN" "run_cmd"
            ;;
    esac
    
    echo "$output"
    return $exit_code
}



# safe_run : 함수 단위 실행 보호 + 상태 로깅
# 실행 형태 : safe_run 함수명 또는 safe_run my_func "$arg1" "$arg2"
safe_run() {
    local func_name="$1"
    shift
    local log_file="$GLOBAL_LOG"


    set +e
    "$func_name" "$@" 2>> "$log_file"
    local exit_code=$?
    set -e

    if [ $exit_code -ne 0 ]; then
        log "❌ $func_name failed (exit code: $exit_code)" "$log_file"
        send_alert "Function Failed" "Function $func_name failed with exit code $exit_code" "WARN" "$func_name"
    else
        log "→ $func_name completed successfully" "$log_file"
    fi
    return $exit_code
}


# 알림 중복 방지를 위한 함수
should_send_alert() {
    local subject="${1:-}"
    local level="${2:-}"
    local message="${3:-}"
    local CACHE_FILE="$LOG_BASE/.alert_sent_cache"
    local now=$(date +%s)

    mkdir -p "$LOG_BASE"
    touch "$CACHE_FILE"

    # 메시지 내용이 없으면 기본 해시 사용
    local msg_hash
    msg_hash=$(echo "${message:-NO_MESSAGE}" | md5sum | awk '{print $1}')
    local cache_line=$(grep "^${subject}|" "$CACHE_FILE" || true)

    # 레벨별 알림 간격 설정
    local interval
    case "$level" in
        "CRIT") interval=600 ;;   # 10분
        "WARN") interval=1800 ;;  # 30분
        "INFO") interval=3600 ;;  # 60분
        *) interval=300 ;;        # 기본값
    esac

    # 기존 캐시에서 해당 subject가 있으면 타임스탬프 확인
    if [ -n "$cache_line" ]; then
        local last_time last_hash count
        last_time=$(echo "$cache_line" | cut -d'|' -f2)
        last_hash=$(echo "$cache_line" | cut -d'|' -f3)
        count=$(echo "$cache_line" | cut -d'|' -f4)
        count=${count:-1}

        if [ "$msg_hash" == "$last_hash" ]; then
            if (( now - last_time < interval )); then
                # 같은 메시지, 시간 제한 내 → 카운트 증가만
                count=$((count + 1))
                sed -i "/^${subject}|/d" "$CACHE_FILE"
                echo "${subject}|${now}|${msg_hash}|${count}" >> "$CACHE_FILE"
                return 1
            fi
        fi

        # 다른 해시거나 시간 초과 → 캐시 갱신
        sed -i "/^${subject}|/d" "$CACHE_FILE"
    fi

    echo "${subject}|${now}|${msg_hash}|1" >> "$CACHE_FILE"
    return 0
}


# send_slack_alert(): Slack으로 알림 전송
send_slack_alert() {
    local subject="$1"
    local message="$2"
    local level="$3"

    # Slack 알림이 비활성화되었거나 웹훅 URL이 없으면 종료
    if [ "$ENABLE_SLACK_ALERTS" != "true" ] || [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
        return 0
    fi

    local emoji=""
    local color=""

    case "$level" in
        CRIT)
            emoji=":rotating_light:"
            color="#ff0000"
            ;;
        WARN)
            emoji=":warning:"
            color="#ffaa00"
            ;;
        INFO)
            emoji=":information_source:"
            color="#00aaff"
            ;;
        *)
            emoji=":grey_question:"
            color="#cccccc"
            ;;
    esac

    # 슬랙 메시지를 간결하게 포맷 (최대 20줄까지만 출력)
    local formatted_msg=$(echo "$message" | head -20 | sed ':a;N;$!ba;s/\n/\\n/g')

    local payload="{
        \"attachments\": [
            {
                \"color\": \"$color\",
                \"title\": \"$emoji $subject\",
                \"text\": \"$formatted_msg\",
                \"ts\": $(date +%s)
            }
        ]
    }"

    curl --connect-timeout 5 --max-time 10 -s -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$SLACK_WEBHOOK_URL" > /dev/null
}

# send_alert() : 로그에 기록하고, 메일/slack으로 알림 전송
# - CRIT: 항상 이메일 전송.
# - WARN: SEND_WARN_EMAILS가 true이면 이메일 전송.
send_alert() {
    local subject="${1:-Unknown Alert}"
    local message="${2:-(no message)}"
    local level="${3:-INFO}"
    local context="${4:-}"  # 함수명 또는 추가정보

    # context가 제공되면 메시지 앞에 붙임
    if [ -n "$context" ]; then
        message="[$context]\n$message"
    fi
    
    local ALERT_CACHE_FILE="$LOG_BASE/.alert_sent_cache"

    # 모든 알림을 로그에 기록 (INFO도 포함)
    log "[${level}] ${subject}: ${message}" "$LOG_BASE/alerts_$(date +%F).log"
    echo "[$(date '+%F %T')] [${level}] ${subject}: ${message}" >> "$RUN_ALERTS_FILE"
    
    # INFO는 알림 전송하지 않음
    if [ "$level" = "INFO" ]; then
        return
    fi

    # 중복 전송 방지 (최근 5분 내 동일 subject가 있으면 전송하지 않음)
    if ! should_send_alert "$subject" "$level"; then
        return
    fi
    
    local decorated_subject
    if [ "$level" == "CRIT" ]; then
        decorated_subject="-------- !!! [CRIT][$HOST_ID] Server Alert: $subject !!! --------"
    elif [ "$level" == "WARN" ]; then
        decorated_subject="-------- !! [WARN][$HOST_ID] Server Alert: $subject !! --------"
    else
        decorated_subject="[${level}][$HOST_ID] Server Alert: $subject"
    fi

    # # 이메일 전송
    # if [ "$ENABLE_EMAIL_ALERTS" = true ]; then
    #     if [[ "$level" == "CRIT" ]] || { [[ "$level" == "WARN" ]] && [[ "$SEND_WARN_EMAILS" == true ]]; }; then
    #         # 이메일 전송  (쉼표 구분된 여러 메일 주소 지원)
    #         IFS=',' read -ra RECIPIENTS <<< "$ALERT_EMAIL"
    #         for email in "${RECIPIENTS[@]}"; do
    #             echo -e "$message" | mail -s "$decorated_subject" "$email"
    #         done
    #     fi

    # fi

    # 이메일 전송 (CRIT 무조건 / WARN은 설정 시 전송)
    if [ "$ENABLE_EMAIL_ALERTS" = true ] && \
    { [ "$level" = "CRIT" ] || { [ "$level" = "WARN" ] && [ "$SEND_WARN_EMAILS" = true ]; }; }; then
        # 이메일 전송  (쉼표 구분된 여러 메일 주소 지원)
        IFS=',' read -ra RECIPIENTS <<< "$ALERT_EMAIL"
        for email in "${RECIPIENTS[@]}"; do
            if echo -e "$message" | mail -s "$decorated_subject" "$email"; then
                log "→ Email sent to $email (level: $level)" "$LOG_BASE/alerts_$(date +%F).log"
            else
                log "❌ Failed to send email to $email (level: $level)" "$LOG_BASE/alerts_$(date +%F).log"
            fi
        done
    fi

    # Slack 알림 전송: ENABLE_SLACK_ALERTS가 true일 경우
    if [ "$ENABLE_SLACK_ALERTS" = true ]; then
        local slack_message=$(echo "$message" | head -30 | sed ':a;N;$!ba;s/\n/\\n/g' | cut -c1-3500)
        send_slack_alert "$decorated_subject" "$slack_message" "$level"
    fi
}

# 전역 오류 핸들러: 스크립트 내 어떤 함수에서 오류가 발생해도 로그와 알림을 남김
error_handler() {
    local exit_code=$?
    local line_no=${BASH_LINENO[0]}
    local err_msg="Script terminated unexpectedly at line $line_no with exit code $exit_code"
    echo "[$(date '+%F %T')] [CRIT] $err_msg" >> "$GLOBAL_LOG"
    
    if [ "$(type -t send_alert)" = "function" ]; then
        send_alert "Script Error" "$err_msg" "CRIT" "error_handler"
    else
        echo "[CRIT] $err_msg"
    fi
    exit $exit_code
}
trap error_handler ERR

### [1] 시스템 요약 ################################################
# 시스템의 기본 정보, 리소스 사용량, 네트워크 상태 등을 로그에 기록
collect_system_summary() {
    local LOG_FILE="$LOG_BASE/system_summary_$(date +%F).log"
    log "====== collect_system_summary ======" "$LOG_FILE"
    
    # 시스템 정보 및 uptime 기록
    log "--- System Info ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" uname -a >> "$LOG_FILE" || true
    run_cmd "$LOG_FILE" uptime >> "$LOG_FILE" || true
        
    # 재부팅 감지: uptime이 10분 미만이면 WARN 알림
    local uptime_min=$(awk '{print int($1 / 60)}' /proc/uptime)
    if [ "$uptime_min" -lt 10 ]; then
        send_alert "Server Recently Rebooted" "Uptime is only ${uptime_min} minutes. Verify if reboot was expected." "WARN" "collect_system_summary ($LOG_FILE)"
    fi
    
    # CPU 로드 및 사용량
    log "--- CPU Usage ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" top -bn1 | head -n 5 >> "$LOG_FILE" || true
    
    # 메모리 정보
    log "--- Memory Info ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" free -h >> "$LOG_FILE" || true
    
    # 스왑 사용량
    log "--- Swap Usage ---" "$LOG_FILE"

    run_cmd "$LOG_FILE" swapon --show || true

    # 디스크 정보
    log "--- Disk Usage ---" "$LOG_FILE"
    # run_cmd "$LOG_FILE" df -h >> "$LOG_FILE" || true
    df -h 2>/dev/null | grep -v "gvfs" >> "$LOG_FILE" || true
    
    # 네트워크 정보
    log "--- Network Info ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ip -s addr >> "$LOG_FILE" || true
    
    # 로그인된 사용자
    log "--- Logged in Users ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" w >> "$LOG_FILE" || true
}


check_reboot_event() {
    local LOG_FILE="$LOG_BASE/reboot_check_$(date +%F).log"
    log "====== check_reboot_event ======" "$LOG_FILE"

    # 최근 부팅 시간 확인
    local last_boot_time
    last_boot_time=$(who -b | awk '{print $3 " " $4}')

    # 기록된 이전 부팅 시간과 비교
    local REBOOT_TRACK_FILE="$LOG_BASE/.last_boot_record"
    if [ -f "$REBOOT_TRACK_FILE" ]; then
        local prev_boot_time
        prev_boot_time=$(cat "$REBOOT_TRACK_FILE")

        if [ "$last_boot_time" != "$prev_boot_time" ]; then
            # 알람 보냄
            local reboot_history
            reboot_history=$(last -x | grep reboot | head -5 || echo "(no history)")

            local reboot_reason=""
            if command -v journalctl &>/dev/null; then
                reboot_reason=$(journalctl -b -1 -n 50 | grep -iE 'panic|crash|fail' | tail -10)
            else
                reboot_reason="journalctl not available on this system."
            fi

            local msg="Detected server reboot.\n\nPrevious boot: $prev_boot_time\nCurrent boot: $last_boot_time\n\nRecent reboot events:\n$reboot_history\n\nReboot cause clues:\n$reboot_reason"
            send_alert "Server Reboot Detected" "$msg" "CRIT" "check_reboot_event ($LOG_FILE)"
        fi
    else
        log "→ First run: recording current boot time" "$LOG_FILE"
    fi

    echo "$last_boot_time" > "$REBOOT_TRACK_FILE"
}

### [2] 디스크 사용량 체크 #########################################
# 각 마운트 지점의 디스크와 inode 사용량을 확인하여 임계치 초과 시 알림을 보냄
# 사용량이 DISK_WARN 또는 DISK_CRIT를 초과하면 각각 WARN 또는 CRIT 알림을 발송합니다
check_disk_usage() {
    local LOG_FILE="$LOG_BASE/disk_usage_$(date +%F).log"
    log "====== check_disk_usage ======" "$LOG_FILE"
    
    # 이전 디스크 사용량 기록 파일
    local PREVIOUS_USAGE_FILE="$LOG_BASE/.prev_disk_usage"
    
    # 1. 모든 디스크 정보 출력 (전체 정보)
    log "--- Complete Disk Information ---" "$LOG_FILE"
    df -h >> "$LOG_FILE"
    
    # 현재 디스크 정보 저장
    local current_disk_info
    current_disk_info=$(df -h | grep -vE '^Filesystem|tmpfs|udev')
    
    # 2. 디스크 사용량 체크: 각 마운트의 사용률을 확인하여 임계치를 초과하면 알림
    local disk_warn_report
    disk_warn_report=$(echo "$current_disk_info" | awk -v threshold="$DISK_WARN" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    
    if [ -n "$disk_warn_report" ]; then
        send_alert "Disk Usage Warning" "Disks over ${DISK_WARN}% usage:\n$disk_warn_report" "WARN" "check_disk_usage ($LOG_FILE)"
    fi
    
    # 3. 디스크 사용량 체크: 치명 임계치 초과 확인
    local disk_crit_report
    disk_crit_report=$(echo "$current_disk_info" | awk -v threshold="$DISK_CRIT" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    
    if [ -n "$disk_crit_report" ]; then
        send_alert "Disk Usage Critical" "Disks over ${DISK_CRIT}% usage:\n$disk_crit_report" "CRIT" "check_disk_usage ($LOG_FILE)"
    fi
    
    # 4. 디스크 사용량 변화 감지 (이전 측정값과 비교)
    if [ -f "$PREVIOUS_USAGE_FILE" ]; then
        log "--- Disk Usage Changes ---" "$LOG_FILE"
        
        # 현재 디스크 정보를 처리하기 쉬운 형식으로 변환
        local tmp_current=$(mktemp)
        echo "$current_disk_info" | awk '{print $1, $3, $5, $6}' > "$tmp_current"
        
        while read -r fs_name used_size used_percent mount_point; do
            # 중요 마운트 포인트만 체크 (불필요한 알림 방지)
            if echo "$mount_point" | grep -qE '^/$|^/data|^/var|^/home'; then
                # 숫자와 단위 분리
                local used_num="${used_size//[^0-9.]/}"
                local fs_unit="${used_size//[0-9.]/}"
                
                # 이전 사용량 찾기
                local prev_line=$(grep "^$fs_name " "$PREVIOUS_USAGE_FILE" 2>/dev/null)
                
                if [ -n "$prev_line" ]; then
                    local prev_used_size=$(echo "$prev_line" | awk '{print $2}')
                    local prev_used_num="${prev_used_size//[^0-9.]/}"
                    local prev_fs_unit="${prev_used_size//[0-9.]/}"
                    
                    # GB 단위로 통일하여 비교
                    local curr_gb="$used_num"
                    local prev_gb="$prev_used_num"
                    
                    # 단위 변환
                    case "$fs_unit" in
                        "T") curr_gb=$(echo "$used_num * 1024" | bc) ;;
                        "M") curr_gb=$(echo "$used_num / 1024" | bc) ;;
                        "K") curr_gb=$(echo "$used_num / 1024 / 1024" | bc) ;;
                    esac
                    
                    case "$prev_fs_unit" in
                        "T") prev_gb=$(echo "$prev_used_num * 1024" | bc) ;;
                        "M") prev_gb=$(echo "$prev_used_num / 1024" | bc) ;;
                        "K") prev_gb=$(echo "$prev_used_num / 1024 / 1024" | bc) ;;
                    esac
                    
                    # 갑작스러운 증가 감지
                    local diff_gb
                    diff_gb=$(echo "$curr_gb - $prev_gb" | bc)
                    
                    if (( $(echo "$diff_gb >= $DISK_INCREASE_THRESHOLD_GB" | bc -l) )); then
                        send_alert "Sudden Disk Usage Increase" "Filesystem $fs_name ($mount_point) increased by ${diff_gb}GB (from ${prev_used_size} to ${used_size})" "WARN" "check_disk_usage ($LOG_FILE)"
                        log "⚠️ Significant increase on $fs_name ($mount_point): +${diff_gb}GB" "$LOG_FILE"
                    fi
                fi
            fi
        done < "$tmp_current"
        
        rm -f "$tmp_current"
    else
        log "→ No previous disk usage data for comparison" "$LOG_FILE"
    fi
    
    # 5. 현재 디스크 사용량 저장 (다음 실행을 위해)
    echo "$current_disk_info" | awk '{print $1, $3, $5, $6}' > "$PREVIOUS_USAGE_FILE"
    
    # 6. inode 사용량 체크
    log "--- Inode Usage Check ---" "$LOG_FILE"
    df -i >> "$LOG_FILE"
    
    local inode_warn_report
    inode_warn_report=$(df -i | grep -vE '^Filesystem|tmpfs|udev' | awk -v threshold="$DISK_WARN" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    if [ -n "$inode_warn_report" ]; then
        send_alert "Inode Usage Warning" "High inode usage (>${DISK_WARN}%):\n$inode_warn_report" "WARN" "check_disk_usage ($LOG_FILE)"
    fi
    
    local inode_crit_report
    inode_crit_report=$(df -i | grep -vE '^Filesystem|tmpfs|udev' | awk -v threshold="$DISK_CRIT" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    
    if [ -n "$inode_crit_report" ]; then
        send_alert "Inode Usage Critical" "Critical inode usage (>${DISK_CRIT}%):\n$inode_crit_report" "CRIT" "check_disk_usage ($LOG_FILE)"
    fi
    
    log "→ check_disk_usage completed" "$LOG_FILE"

    # # 큰 파일 체크: 10GB 이상의 파일 목록을 기록 (불필요한 파일 정리 참고) -> 해당 부분 메모리 부하 발생 하는 것 같아서 제외
    # log "--- Large Files (>10GB) ---" "$LOG_FILE"
    # run_cmd "$LOG_FILE" find /home /var /data1 /data2 -type f -size +10G -printf '%s %p\n' 2>/dev/null | \
    #   sort -nr | head -10 | awk '{ printf "%10d KB  %s\n", $1/1024, $2 }' >> "$LOG_FILE"  || true
}
 
 


### [3] 도커 볼륨 감시 ############################################
# 도커가 설치되어 있다면 각 도커 볼륨의 사용량을 점검하여 로그에 기록합니다.
# 도커 명령어가 없으면 CRIT 알림을 발송합니다.
check_docker_volume_usage() {
    local LOG_FILE="$LOG_BASE/docker_volume_usage_$(date +%F).log"
    log "====== check_docker_volume_usage ======" "$LOG_FILE"

    if command -v docker &>/dev/null; then
        run_cmd "$LOG_FILE" docker volume ls -q | while read volume; do
            local mountpoint usage
            mountpoint=$(run_cmd "$LOG_FILE" timeout 5s docker volume inspect "$volume" -f '{{ .Mountpoint }}')
            if [ -d "$mountpoint" ]; then
                usage=$(du -sh "$mountpoint" 2>/dev/null | awk '{print $1}')
                log "Volume: $volume ($mountpoint) → $usage" "$LOG_FILE"
            fi
        done || true
    else
        log "❌ Docker command not found. Docker volume monitoring skipped." "$LOG_FILE"
        send_alert "Docker Missing" "Docker command not found but is expected. Docker volume monitoring is disabled." "WARN" "check_docker_volume_usage ($LOG_FILE)"
    fi
}

### [4] 네트워크 상태 체크 ########################################
# 네트워크 연결, 대역폭, 핑 테스트, DNS 해상도 등을 점검하여 이상 시 경고
check_network_status() {
    local LOG_FILE="$LOG_BASE/net_status_$(date +%F).log"
    log "========= check_network_status =========" "$LOG_FILE"

    # 현재 연결 상태
    log "--- Network Connections ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ss -tuna | head -20 >> "$LOG_FILE" || true
    
    # 연결 상태 통계
    log "--- Connection Statistics ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ss -s >> "$LOG_FILE" || true

    # 대역폭 사용량 측정 (ifstat가 설치된 경우)
    if command -v ifstat &> /dev/null; then
        log "--- Bandwidth Usage ---" "$LOG_FILE"
        # 주요 인터페이스 자동 감지
        # local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em|bond|wlan)')
        # run_cmd "$LOG_FILE" ifstat -i $(echo "$interfaces" | tr '\n' ',') -b 1 1

        local interfaces=()
        while IFS= read -r iface; do
            interfaces+=("$iface")
        done < <(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em|bond|wlan)')

        if [ ${#interfaces[@]} -gt 0 ]; then
            log "Detected interfaces: ${interfaces[*]}" "$LOG_FILE"
            for iface in "${interfaces[@]}"; do
                log "→ Bandwidth for $iface" "$LOG_FILE"
                # RedHat 호환: -b 옵션 없이 실행
                # run_cmd "$LOG_FILE" ifstat "$iface" 1 1 || log "⚠️ ifstat failed for $iface" "$LOG_FILE"
                ifstat "$iface" 1 1 >> "$LOG_FILE" 2>&1 || log "⚠️ ifstat failed for $iface" "$LOG_FILE"

            done
        else
            log "⚠️ No network interfaces found for bandwidth check." "$LOG_FILE"
        fi
    fi

    # 핑 테스트
    log "--- Ping Tests ---" "$LOG_FILE"
    local ping_failures=0
    for target in "${PING_TARGETS[@]}"; do
        log "Pinging $target..." "$LOG_FILE"
        if ! run_cmd "$LOG_FILE" timeout 10s ping -c 3 -W 2 "$target" >> "$LOG_FILE" 2>&1; then
            ping_failures=$((ping_failures + 1))
            log "⚠️ Failed to ping $target" "$LOG_FILE"
        fi
    done
    
    if [ $ping_failures -gt 0 ]; then
        send_alert "Network Connectivity Issues" "Failed to ping $ping_failures out of ${#PING_TARGETS[@]} targets." "WARN" "check_network_status ($LOG_FILE)"
    fi

    # DNS 해상도 테스트
    log "--- DNS Resolution Test ---" "$LOG_FILE"
    
    # 여러 도메인을 테스트
    local dns_domains=("google.com" "naver.com" "github.com")
    local dns_failures=0
    local dns_success=0
    
    # 각 도메인에 대해 테스트
    for domain in "${dns_domains[@]}"; do
        if run_cmd "$LOG_FILE" timeout 10s host -t A "$domain" >> "$LOG_FILE" 2>&1; then
            dns_success=$((dns_success + 1))
            log "✅ Successfully resolved $domain" "$LOG_FILE"
        else
            dns_failures=$((dns_failures + 1))
            log "⚠️ Failed to resolve $domain" "$LOG_FILE"
            
            # 첫 번째 호스트 실패 시 dig 명령어로 재시도 (가능한 경우)
            if command -v dig &>/dev/null; then
                log "Trying alternate DNS lookup with dig for $domain..." "$LOG_FILE"
                if run_cmd "$LOG_FILE" timeout 10s dig +short "$domain" >> "$LOG_FILE" 2>&1; then
                    dns_failures=$((dns_failures - 1))
                    dns_success=$((dns_success + 1))
                    log "✅ Successfully resolved $domain using dig" "$LOG_FILE"
                fi
            fi
        fi
    done
    
    # 모든 도메인 해결 실패 시에만 경고
    if [ $dns_success -eq 0 ] && [ $dns_failures -gt 0 ]; then
        send_alert "DNS Resolution Failure" "Failed to resolve any domain names. Check DNS configuration." "WARN" "check_network_status ($LOG_FILE)"
    elif [ $dns_failures -gt 0 ]; then
        log "⚠️ Some DNS lookups failed but at least one succeeded - not triggering alert" "$LOG_FILE"
    fi
    
    # 연결 상태 분석
    log "--- Connection State Analysis ---" "$LOG_FILE"
    local established=$(ss -tan | grep ESTAB | wc -l) || true
    local time_wait=$(ss -tan | grep TIME-WAIT | wc -l) || true
    local close_wait=$(ss -tan | grep CLOSE-WAIT | wc -l) || true
    
    log "Established: $established, Time-Wait: $time_wait, Close-Wait: $close_wait" "$LOG_FILE"
    
    # CLOSE_WAIT 상태가 많으면 소켓 누수 가능성 경고
    if [ "$close_wait" -gt 100 ]; then
        send_alert "Socket Leak Warning" "Detected $close_wait CLOSE_WAIT connections. Possible socket leak in applications." "WARN" "check_network_status ($LOG_FILE)"
    fi
    
    # TIME_WAIT 상태가 매우 많으면 커널 설정 검토 제안
    if [ "$time_wait" -gt 1000 ]; then
        log "⚠️ High number of TIME_WAIT connections: $time_wait. Consider tuning tcp_tw_reuse and tcp_tw_recycle." "$LOG_FILE"
    fi
}


### [5] 프로세스 리소스 과다 #######################################
# CPU 또는 메모리 사용량이 높은 프로세스를 점검합니다.
# - 도커 컨테이너에 속한 경우, 컨테이너 이름에 중요 키워드(예: db, prod 등)가 없으면 재시작을 시도합니다.
#   중요 컨테이너인 경우 치명 알림(CRIT)을 발송합니다.
# - 일반 프로세스인 경우, SIGTERM 후 종료되지 않으면 SIGKILL으로 강제 종료합니다.
# 
# CONSECUTIVE_LIMIT 변수를 사용하여, 동일 프로세스가 3회 연속 임계치를 초과한 경우에만 강제 종료 또는 컨테이너 재시작을 시도
check_process_usage() {
    local LOG_FILE="$LOG_BASE/proc_usage_$(date +%F).log"
    log "====== check_process_usage ======" "$LOG_FILE"

    local TMP_FILE=$(mktemp "${LOG_BASE}/.tmp_high_usage_pids.XXXXXX")
    local CPU_COUNT=$(nproc)
    local CPU_THRESHOLD=$(echo "$CPU_COUNT * $CPU_WARN_PERCENT / 100" | bc | awk '{printf "%.0f", $1}')  #  CPU 임계치 : CPU 코어 수 * 경고 비율
    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local MEM_THRESHOLD=$((MEM_TOTAL * MEM_WARN_PERCENT / 100))  # 메모리 임계치 : 전체 메모리의 경고 비율
    local CONSECUTIVE_LIMIT=3  # 연속 감지 횟수 (조건 초과가 연속적으로 발생해야 조치)
    
    touch "$TMP_FILE"
    
    # 높은 CPU/메모리 사용량 프로세스 기록
    log "--- High Resource Usage Processes ---" "$LOG_FILE"
    # 개별 로그에 프로세스 출력 기록 (오류 발생해도 종료되지 않도록 || true 추가)
    run_cmd "$LOG_FILE" ps -eo pid,ppid,user,pcpu,pmem,rss,cmd --sort=-%cpu | head -10 >> "$LOG_FILE" || true
    run_cmd "$LOG_FILE" ps -eo pid,ppid,user,pcpu,pmem,rss,cmd --sort=-%mem | head -10 >> "$LOG_FILE" || true
    
    # 산출된 프로세스 목록을 읽을 때 set +e로 오류 무시 (파이프라인 오류로 인한 종료 방지)
    set +e
    ps -eo pid,comm,pcpu,pmem,rss --sort=-%cpu | awk 'NR>1' | while read pid cmd cpu pmem rss; do
        local mem_mb=0
        if [[ "$rss" =~ ^[0-9]+$ ]]; then
            mem_mb=$(( rss / 1024 ))
        fi

        # 화이트리스트: 시스템 관련 또는 관리 스크립트는 자동 조치하지 않음.
        if echo "$cmd" | grep -qiE "(systemd|sshd|init|monitoring)"; then
            continue
        fi

        # CPU와 메모리 사용률 모두 임계치를 초과하는 경우에만 조치 (연속 감지 필요)
        # bc의 결과는 "1" (참) 또는 "0" (거짓)로 반환되므로, 비교를 [ ... ]로 처리
	    if [[ "$cpu" =~ ^[0-9.]+$ && "$mem_mb" =~ ^[0-9]+$ ]]; then
            if [ "$(echo "$cpu > $CPU_THRESHOLD" | bc -l)" -eq 1 ] && [ "$mem_mb" -gt "$MEM_THRESHOLD" ]; then
                # 과도한 리소스 사용 프로세스 감지
                local hit_count
                hit_count=$(grep -c "^$pid " "$TMP_FILE" 2>/dev/null || echo 0)
                if [ "$hit_count" -ge "$CONSECUTIVE_LIMIT" ]; then
                    local proc_owner proc_detail
                    proc_owner=$(ps -o user= -p "$pid")
                    proc_detail=$(ps -p "$pid" -o pid,ppid,user,cmd | tail -1)
                    
                    # 만약 프로세스 명령어에 중요 서비스(웹서버, DB 등)가 포함되어 있다면,
                    # 자동 종료 대신 치명(CRIT) 알림을 발송하여 수동 개입을 요청합니다.
                    if echo "$cmd" | grep -qiE "(httpd|nginx|mysql|postgres|mongo|redis|java|node|tomcat)"; then
                        send_alert "Critical Process High Load" "Critical process $pid ($cmd) by $proc_owner using CPU:${cpu}% MEM:${mem_mb}MB. Manual check required." "CRIT" "check_process_usage ($LOG_FILE)"
                    else
                        # Docker 컨테이너 여부 확인
                        local container_id
                        container_id=$(cat /proc/$pid/cgroup 2>/dev/null | grep "docker" | awk -F/ '{print $3}' | head -1)
                        if [ -n "$container_id" ]; then
                            local container_name
                            container_name=$(timeout 5s docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null | sed 's/^\///')
                            log "→ Container $container_name ($container_id) has high resource usage processes" "$LOG_FILE"
                            docker stats --no-stream "$container_id" >> "$LOG_FILE" 2>&1 || true
                            # 중요 컨테이너(예: db, prod 등)는 자동 재시작하지 않고 치명 알림
                            if echo "$container_name" | grep -qiE "(db|database|data|main|prod|api)"; then
                                send_alert "Critical Container High Load" "Critical container $container_name has high resource usage. Manual check required." "CRIT" "check_process_usage($LOG_FILE)"
                            else
                                log "→ Restarting container $container_name" "$LOG_FILE"
                                docker restart "$container_id" >> "$LOG_FILE" 2>&1 || true
                                if [ $? -eq 0 ]; then
                                    send_alert "Container Restarted" "$container_name restarted due to high usage." "INFO" "check_process_usage ($LOG_FILE)"
                                else
                                    send_alert "Container Restart Failed" "Failed to restart $container_name" "CRIT" "check_process_usage ($LOG_FILE)"
                                fi
                            fi
                        else
                            # 일반 프로세스: 강제 종료를 시도
                            log "→ Sending SIGTERM to PID $pid" "$LOG_FILE"
                            run_cmd "$LOG_FILE" kill "$pid" >> "$LOG_FILE" 2>&1 || true
                            sleep 2
                            
                            # SIGTERM 후에도 실행 중이면 SIGKILL
                            if run_cmd "$LOG_FILE" kill -0 "$pid" 2>/dev/null; then 
                                log "→ Process did not terminate, sending SIGKILL to PID $pid" "$LOG_FILE"
                                run_cmd "$LOG_FILE" kill -9 "$pid" >> "$LOG_FILE" 2>&1 || true
                                send_alert "Process Killed" "Killed process $pid ($cmd) due to high resource usage" "WARN" "check_process_usage ($LOG_FILE)"
                            fi
                        fi
                    fi
                    
                    # 처리된 PID 제거
                    run_cmd "$LOG_FILE" sed -i "/^$pid /d" "$TMP_FILE" 2>/dev/null || true
                else
                    # 연속 감지 카운터 증가
                    run_cmd "$LOG_FILE" echo "$pid $cmd $cpu $mem_mb" >> "$TMP_FILE" || true
                fi
            fi
        fi
    done
    # set +e로 변경한 설정을 복원합니다
    set -e

    if [ -f "$TMP_FILE" ]; then
        local live_pids_file
        live_pids_file=$(mktemp)

        # 현재 살아있는 PID 목록 저장
        ps -eo pid | tail -n +2 > "$live_pids_file"

        # tmp 파일에서 존재하지 않는 pid들 제거
        grep -vFx -f "$live_pids_file" "$TMP_FILE" > "$TMP_FILE.cleaned" 2>/dev/null || true
        mv "$TMP_FILE.cleaned" "$TMP_FILE" 2>/dev/null || true

        rm -f "$live_pids_file"
    fi


    # TMP_FILE 정리: 사용 후 반드시 삭제
    rm -f "$TMP_FILE"
}


### [6] I/O 과다 탐지 ##############################################
# iotop/pidstat 명령어를 사용해 I/O 사용량이 높은 프로세스들을 점검합니다.
check_io_heavy_processes() {
    local LOG_FILE="$LOG_BASE/io_heavy_$(date +%F).log"
    log "====== check_io_heavy_processes ======" "$LOG_FILE"

    if command -v iotop &>/dev/null; then
        run_cmd "$LOG_FILE" timeout 10s iotop -b -n 3 -o >> "$LOG_FILE" 2>/dev/null || true
        
        # I/O 사용량이 높은 프로세스가 있는지 간단히 확인 (옵션)
        local high_io_detected
        high_io_detected=$(grep -E "[0-9]+\.[0-9]+[ ]+[MKG]" "$LOG_FILE" | head -1)
        
        if [ -n "$high_io_detected" ]; then
            log "→ High I/O activity detected, check log for details" "$LOG_FILE"
        else
            log "→ No significant I/O activity detected" "$LOG_FILE"
        fi

    elif command -v pidstat &>/dev/null; then
        # iotop이 없으면 pidstat으로 대체
        log "iotop not found, using pidstat for I/O monitoring..." "$LOG_FILE"

        local tmp_pidstat_log
        tmp_pidstat_log=$(mktemp "${LOG_BASE}/.tmp_pidstat_output.XXXXXX")

        if timeout 10s pidstat -d 1 5 > "$tmp_pidstat_log" 2>&1; then
            awk 'NR > 7 { print }' "$tmp_pidstat_log" >> "$LOG_FILE"
            log "→ pidstat output saved" "$LOG_FILE"
        else
            log "❌ pidstat failed or timed out after 10s" "$LOG_FILE"
            send_alert "pidstat Timeout" "pidstat command failed or hung beyond timeout." "WARN" "check_io_heavy_processes ($LOG_FILE)"
        fi

        rm -f "$tmp_pidstat_log"

    else
        # 둘 다 없는 경우 대체 명령어로 I/O 상태 확인
        log "I/O monitoring tools not found. Using alternative methods..." "$LOG_FILE"
        
        # 1. /proc/diskstats를 통한 디스크 I/O 확인
        log "--- Disk I/O Stats ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" cat /proc/diskstats | grep -E 'sd|nvme|vd' | awk '{print $3": "$6" reads, "$10" writes"}' >> "$LOG_FILE" || true
        
        # 2. top 명령어로 CPU 사용량 높은 프로세스 확인
        log "--- Top Processes (CPU) ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" top -b -n 1 -o %CPU | head -20 >> "$LOG_FILE" || true

        log "--- Process States ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" ps aux --sort=-pcpu | head -10 >> "$LOG_FILE" || true

        if command -v vmstat &>/dev/null; then
            local io_wait
            io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')
            log "→ System I/O wait: $io_wait%" "$LOG_FILE"
            
            if [ "$io_wait" -gt 20 ]; then
                send_alert "High System I/O Wait" "System has high I/O wait time ($io_wait%). Consider checking disk performance." "WARN" "check_io_heavy_processes ($LOG_FILE)"
            fi
        fi
    fi

    # ripgrep 특별 감지 로직 추가
    if ps aux | grep -E "(rg|ripgrep)" | grep -v grep; then
        local rg_processes=$(ps aux | grep -E "(rg|ripgrep)" | grep -v grep)
        log "🎯 Detected ripgrep processes:" "$LOG_FILE"
        echo "$rg_processes" >> "$LOG_FILE"
        
        # ripgrep이 대용량 디렉토리에서 실행 중인지 확인
        echo "$rg_processes" | while read line; do
            local pid=$(echo "$line" | awk '{print $2}')
            local cwd=$(readlink /proc/$pid/cwd 2>/dev/null)
            if echo "$cwd" | grep -qE "(data1|data2|labelstudio|dataset)"; then
                send_alert "Ripgrep in Large Directory" \
                    "ripgrep running in large directory: $cwd" \
                    "WARN" "check_io_heavy_processes ($LOG_FILE)"
            fi
        done
    fi


    log "→ check_io_heavy_processes completed" "$LOG_FILE"
}

# 실시간 I/O 부하 감지 및 자동 대응
monitor_realtime_io_load() {
    local LOG_FILE="$LOG_BASE/realtime_io_$(date +%F).log"
    log "====== monitor_realtime_io_load ======" "$LOG_FILE"
    
    # I/O 임계값 설정
    local IO_READ_THRESHOLD_MB=300    # 읽기 300MB/s 이상
    local IO_WRITE_THRESHOLD_MB=200   # 쓰기 200MB/s 이상
    local IO_TOTAL_THRESHOLD_MB=400   # 총 I/O 400MB/s 이상
    local SUSTAINED_DURATION=30       # 지속 시간 (초)
    
    log "--- Real-time I/O Load Monitoring (${SUSTAINED_DURATION}s) ---" "$LOG_FILE"
    
    # iostat으로 실시간 I/O 측정
    if command -v iostat &>/dev/null; then
        local io_data=$(iostat -d 1 $SUSTAINED_DURATION | grep -E "sd[a-z]|nvme")
        echo "$io_data" >> "$LOG_FILE"
        
        # 평균 I/O 계산
        local avg_read_mb avg_write_mb avg_total_mb
        avg_read_mb=$(echo "$io_data" | awk '{sum+=$3} END {printf "%.1f", sum/NR/1024}')
        avg_write_mb=$(echo "$io_data" | awk '{sum+=$4} END {printf "%.1f", sum/NR/1024}')
        avg_total_mb=$(echo "$avg_read_mb + $avg_write_mb" | bc)
        
        log "→ Average I/O over ${SUSTAINED_DURATION}s: Read=${avg_read_mb}MB/s, Write=${avg_write_mb}MB/s, Total=${avg_total_mb}MB/s" "$LOG_FILE"
        
        # 임계값 초과 시 경고
        if (( $(echo "$avg_total_mb > $IO_TOTAL_THRESHOLD_MB" | bc -l) )); then
            detect_io_intensive_processes
            send_alert "Sustained High I/O Load" \
                "Detected sustained high I/O load: ${avg_total_mb}MB/s over ${SUSTAINED_DURATION} seconds (threshold: ${IO_TOTAL_THRESHOLD_MB}MB/s)" \
                "WARN" "monitor_realtime_io_load ($LOG_FILE)"
        fi
    else
        log "❌ iostat not available for real-time I/O monitoring" "$LOG_FILE"
    fi
}

# I/O 집약적 프로세스 실시간 감지 및 자동 조치
detect_io_intensive_processes() {
    local LOG_FILE="$LOG_BASE/io_intensive_$(date +%F).log"
    log "====== detect_io_intensive_processes ======" "$LOG_FILE"
    
    # 현재 I/O 사용량이 높은 프로세스 찾기
    if command -v iotop &>/dev/null; then
        log "--- High I/O Processes (iotop) ---" "$LOG_FILE"
        local high_io_processes=$(timeout 10s iotop -b -n 3 -o | \
            awk 'NR>7 && $9+$11>50 {print $1,$2,$3,$9,$11,$12}' | head -10)
        echo "$high_io_processes" >> "$LOG_FILE"
        
        # 특정 패턴 감지 (ripgrep, find 등)
        local suspicious_processes=$(echo "$high_io_processes" | grep -E "(rg|ripgrep|find|locate)")
        if [ -n "$suspicious_processes" ]; then
            log "🚨 Detected suspicious I/O intensive processes:" "$LOG_FILE"
            echo "$suspicious_processes" >> "$LOG_FILE"
            
            # 자동 조치 옵션
            auto_handle_io_intensive_process "$suspicious_processes"
        fi
        
    elif command -v pidstat &>/dev/null; then
        log "--- High I/O Processes (pidstat) ---" "$LOG_FILE"
        local io_stats=$(pidstat -d 1 3 | awk 'NR>3 && ($4+$5)>1024 {print $3,$4,$5,$8}')
        echo "$io_stats" >> "$LOG_FILE"
    fi
}

# I/O 집약적 프로세스 자동 처리
auto_handle_io_intensive_process() {
    local process_info="$1"
    local LOG_FILE="$LOG_BASE/auto_io_handle_$(date +%F).log"
    log "====== auto_handle_io_intensive_process ======" "$LOG_FILE"
    
    echo "$process_info" | while read pid user io_read io_write cmd; do
        [ -z "$pid" ] && continue
        
        log "→ Analyzing high I/O process: PID=$pid, USER=$user, CMD=$cmd" "$LOG_FILE"
        
        # 프로세스 상세 정보 수집
        local proc_cmd=$(ps -p "$pid" -o cmd= 2>/dev/null)
        local proc_cwd=$(readlink /proc/$pid/cwd 2>/dev/null)
        
        # 검색 관련 프로세스 패턴 감지 (범용적)
        if echo "$proc_cmd" | grep -qE "(rg|ripgrep|grep|find|locate|updatedb|ag|ack)"; then
            log "🔍 Detected search process: $proc_cmd" "$LOG_FILE"
            log "   Working directory: $proc_cwd" "$LOG_FILE"
            
            # 대용량 디렉토리에서 실행되는지 확인
            if echo "$proc_cwd" | grep -qE "(data1|data2|home|var|opt|usr)"; then
                log "   ⚠️ Search running in large directory: $proc_cwd" "$LOG_FILE"
                
                # 프로세스 우선순위 조정 (종료하지 않고)
                renice +15 "$pid" 2>/dev/null
                ionice -c 3 -p "$pid" 2>/dev/null
                
                send_alert "High I/O Search Process" \
                    "High I/O search process detected: PID=$pid, CMD=$proc_cmd, CWD=$proc_cwd. Process priority lowered to reduce system impact." \
                    "WARN" "auto_handle_io_intensive_process ($LOG_FILE)"
            fi
        fi
        
        # 백업/압축 관련 프로세스
        if echo "$proc_cmd" | grep -qE "(tar|gzip|zip|rsync|cp|dd|backup)"; then
            log "💾 Detected backup/compression process: $proc_cmd" "$LOG_FILE"
            
            # 백업 프로세스는 우선순위만 조정 (중요하므로 종료하지 않음)
            renice +10 "$pid" 2>/dev/null
            ionice -c 2 -n 6 -p "$pid" 2>/dev/null
            
            send_alert "High I/O Backup Process" \
                "Backup/compression process with high I/O: PID=$pid, CMD=$proc_cmd. Priority adjusted." \
                "INFO" "auto_handle_io_intensive_process ($LOG_FILE)"
        fi
        
        # 기타 의심스러운 고I/O 프로세스
        if echo "$proc_cmd" | grep -qE "(wget|curl|scp|rsync)" && [[ "$io_read" -gt 1000 ]] || [[ "$io_write" -gt 1000 ]]; then
            log "🌐 Detected high I/O network process: $proc_cmd" "$LOG_FILE"
            
            # 네트워크 관련 프로세스 우선순위 조정
            renice +5 "$pid" 2>/dev/null
            ionice -c 2 -n 4 -p "$pid" 2>/dev/null
            
            send_alert "High I/O Network Process" \
                "Network process with high I/O: PID=$pid, CMD=$proc_cmd" \
                "INFO" "auto_handle_io_intensive_process ($LOG_FILE)"
        fi
    done
}

# 프로세스 I/O 영향도 분석
analyze_process_io_impact() {
    local pid="$1"
    local LOG_FILE="$LOG_BASE/process_io_impact_$(date +%F).log"
    
    # 프로세스의 I/O 통계 수집
    if [ -f "/proc/$pid/io" ]; then
        local io_stats=$(cat /proc/$pid/io 2>/dev/null)
        local read_bytes=$(echo "$io_stats" | grep "read_bytes" | awk '{print $2}')
        local write_bytes=$(echo "$io_stats" | grep "write_bytes" | awk '{print $2}')
        
        log "→ Process $pid I/O stats: Read=${read_bytes} bytes, Write=${write_bytes} bytes" "$LOG_FILE"
        
        # 매우 높은 I/O (1GB 이상) 감지
        if [[ "$read_bytes" -gt 1073741824 ]] || [[ "$write_bytes" -gt 1073741824 ]]; then
            return 1  # High impact
        fi
    fi
    
    return 0  # Normal impact
}

# 디스크별 I/O 패턴 분석
analyze_disk_io_patterns() {
    local LOG_FILE="$LOG_BASE/disk_io_patterns_$(date +%F).log"
    log "====== analyze_disk_io_patterns ======" "$LOG_FILE"
    
    # 각 디스크의 I/O 패턴 분석
    local PATTERN_FILE="$LOG_BASE/.disk_io_history"
    local current_io=$(iostat -d 1 1 | awk 'NR>3 {print $1,$4,$5}')
    
    log "--- Current Disk I/O Rates ---" "$LOG_FILE"
    echo "$current_io" >> "$LOG_FILE"
    
    # 이전 데이터와 비교
    if [ -f "$PATTERN_FILE" ]; then
        log "--- I/O Pattern Changes ---" "$LOG_FILE"
        
        while read disk read_kb write_kb; do
            [ -z "$disk" ] && continue
            
            local prev_read=$(grep "^$disk " "$PATTERN_FILE" | awk '{print $2}')
            local prev_write=$(grep "^$disk " "$PATTERN_FILE" | awk '{print $3}')
            
            if [ -n "$prev_read" ] && [ -n "$prev_write" ]; then
                local read_diff=$((read_kb - prev_read))
                local write_diff=$((write_kb - prev_write))
                
                # 급격한 I/O 증가 감지 (10배 이상)
                if [ "$read_diff" -gt $((prev_read * 10)) ] || [ "$write_diff" -gt $((prev_write * 10)) ]; then
                    log "🚨 Sudden I/O spike on $disk: Read +${read_diff}KB/s, Write +${write_diff}KB/s" "$LOG_FILE"
                    
                    # 해당 디스크를 사용하는 프로세스 찾기
                    find_processes_using_disk "$disk"
                    
                    send_alert "Disk I/O Spike" \
                        "Sudden I/O increase on $disk: Read +${read_diff}KB/s, Write +${write_diff}KB/s" \
                        "WARN" "analyze_disk_io_patterns ($LOG_FILE)"
                fi
            fi
        done <<< "$current_io"
    fi
    
    # 현재 데이터 저장
    echo "$current_io" > "$PATTERN_FILE"
}

# 특정 디스크를 사용하는 프로세스 찾기
find_processes_using_disk() {
    local disk="$1"
    local LOG_FILE="$LOG_BASE/disk_processes_$(date +%F).log"
    log "====== find_processes_using_disk: $disk ======" "$LOG_FILE"
    
    # 해당 디스크의 마운트 포인트 찾기
    local mount_point=$(df | grep "^/dev/$disk" | awk '{print $6}')
    
    if [ -n "$mount_point" ]; then
        log "→ Disk $disk mounted at: $mount_point" "$LOG_FILE"
        
        # 해당 마운트 포인트를 사용하는 프로세스 찾기
        log "--- Processes using $mount_point ---" "$LOG_FILE"
        lsof +D "$mount_point" 2>/dev/null | head -20 >> "$LOG_FILE" || \
        fuser -v "$mount_point" 2>&1 | head -20 >> "$LOG_FILE" || \
        log "Cannot determine processes using $mount_point" "$LOG_FILE"
    fi
}

# 시스템 I/O 영향도 기반 프로세스 관리
manage_io_intensive_processes() {
    local LOG_FILE="$LOG_BASE/manage_io_processes_$(date +%F).log"
    log "====== manage_io_intensive_processes ======" "$LOG_FILE"
    
    # 높은 I/O 사용 프로세스 찾기
    local high_io_pids=()
    if command -v iotop &>/dev/null; then
        mapfile -t high_io_pids < <(iotop -b -n 1 -o | awk 'NR>7 && ($9+$11)>25 {print $1}' | head -10)
    elif command -v pidstat &>/dev/null; then
        mapfile -t high_io_pids < <(pidstat -d 1 1 | awk 'NR>3 && ($4+$5)>100 {print $3}' | head -10)
    fi
    
    for pid in "${high_io_pids[@]}"; do
        [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]] && continue
        
        local cmd=$(ps -p "$pid" -o comm= 2>/dev/null)
        local full_cmd=$(ps -p "$pid" -o cmd= 2>/dev/null)
        
        # 시스템 중요 프로세스 제외
        if echo "$cmd" | grep -qE "^(systemd|kthreadd|ksoftirqd|migration|rcu_|watchdog)"; then
            continue
        fi
        
        # 프로세스 유형별 처리
        case "$cmd" in
            "find"|"locate"|"updatedb"|"grep"|"rg"|"ag"|"ack")
                log "🔍 Managing search process: $cmd (PID: $pid)" "$LOG_FILE"
                renice +15 "$pid" 2>/dev/null
                ionice -c 3 -p "$pid" 2>/dev/null
                ;;
            "tar"|"gzip"|"zip"|"rsync"|"cp"|"dd")
                log "💾 Managing backup/compression process: $cmd (PID: $pid)" "$LOG_FILE"
                renice +10 "$pid" 2>/dev/null
                ionice -c 2 -n 6 -p "$pid" 2>/dev/null
                ;;
            "wget"|"curl"|"scp")
                log "🌐 Managing network process: $cmd (PID: $pid)" "$LOG_FILE"
                renice +5 "$pid" 2>/dev/null
                ionice -c 2 -n 4 -p "$pid" 2>/dev/null
                ;;
            *)
                # 알 수 없는 고I/O 프로세스
                if analyze_process_io_impact "$pid"; then
                    log "❓ Unknown high I/O process: $cmd (PID: $pid)" "$LOG_FILE"
                    send_alert "Unknown High I/O Process" \
                        "Unknown process with high I/O detected: PID=$pid, CMD=$full_cmd" \
                        "WARN" "manage_io_intensive_processes ($LOG_FILE)"
                fi
                ;;
        esac
    done
}

# 메인 I/O 모니터링 통합 함수
enhanced_io_monitoring() {
    local LOG_FILE="$LOG_BASE/enhanced_io_$(date +%F).log"
    log "====== enhanced_io_monitoring ======" "$LOG_FILE"
    
    # 기존 I/O 체크 실행
    safe_run check_io_heavy_processes
    safe_run manage_io_bottleneck
    
    # 새로운 향상된 I/O 모니터링
    safe_run monitor_realtime_io_load
    safe_run analyze_disk_io_patterns
    safe_run manage_io_intensive_processes
    
    log "→ Enhanced I/O monitoring completed" "$LOG_FILE"
}

### [7] 서비스 상태 및 컨테이너 체크 ##############################
# 지정된 서비스들이 정상적으로 실행 중인지 확인합니다.
# 서비스가 비활성일 경우 재시작을 시도하고, 재시작 실패 시 CRIT 알림을 발송합니다.
# 또한 도커 컨테이너의 상태를 점검하여, 중지된 컨테이너가 있으면 WARN 알림을 발송합니다.
check_services() {
    local LOG_FILE="$LOG_BASE/service_status_$(date +%F).log"
    log "====== check_services ======" "$LOG_FILE"
    
    for svc in "${SERVICES[@]}"; do
        # 서비스 존재 여부 먼저 확인 (없는 서비스는 skip)
        if ! systemctl list-unit-files | grep -qw "$svc.service"; then
            log "→ Service $svc not found, skipping." "$LOG_FILE"
            continue
        fi

        run_cmd "$LOG_FILE" systemctl is-active --quiet "$svc" || true
        local status=$?
        
        # Kubernetes 환경에서 docker 서비스가 비활성일 경우 무시
        if [ "$svc" = "docker" ] && [ "$status" -ne 0 ]; then
            if is_kubernetes_node; then ######## sim-test
                log "→ Docker service is not active, but running in Kubernetes. Ignoring." "$LOG_FILE"
                continue
            fi
        fi

        if [ $status -ne 0 ]; then
            # 서비스가 실행 중이지 않으면 상태 정보를 기록하고 재시작 시도
            run_cmd "$LOG_FILE" systemctl status "$svc" --no-pager | head -15 >> "$LOG_FILE" || true
            send_alert "Service Down" "Service $svc is NOT running (status: $status)" "CRIT" "check_services ($LOG_FILE)"
            
            # 서비스 재시작 시도
            log "→ Attempting to restart $svc" "$LOG_FILE"
            run_cmd "$LOG_FILE" systemctl restart "$svc" >> "$LOG_FILE" 2>&1 || true
            sleep 2
            
            # 재시작 후 상태 확인
            run_cmd "$LOG_FILE" systemctl is-active --quiet "$svc" || true
            if [ $? -ne 0 ]; then
                send_alert "Service Restart Failed" "Failed to restart service $svc" "CRIT" "check_services ($LOG_FILE)"
            else
                send_alert "Service Restarted" "Successfully restarted service $svc" "INFO" "check_services ($LOG_FILE)"
            fi
        else
            log "→ Service $svc is active" "$LOG_FILE"
        fi
    done

    # Docker 컨테이너 상태 확인 (docker 명령어가 존재할 경우)
    if command -v docker &> /dev/null; then
        log "--- Docker Container Status ---" "$LOG_FILE"

        run_cmd "$LOG_FILE" timeout 5s docker ps -a >> "$LOG_FILE" || true
        local stopped_containers
        # 중지된 컨테이너 확인
        stopped_containers=$(run_cmd "$LOG_FILE" timeout 5s docker ps -f "status=exited" -q)
        if [ -n "$stopped_containers" ]; then
            log "→ Found stopped containers: $stopped_containers" "$LOG_FILE"
            send_alert "Stopped Containers" "Some Docker containers are not running" "INFO"  "check_services ($LOG_FILE)"
        fi
    fi
}

### [8] 시스템 온도 모니터링  ################################
# lm-sensors를 사용해 시스템 온도를 점검합니다.
# 온도가 TEMP_THRESHOLD(80°C) 이상이면 WARN 알림을 발송합니다.
check_system_temperature() {
    local LOG_FILE="$LOG_BASE/temp_status_$(date +%F).log"
    log "====== check_system_temperature ======" "$LOG_FILE"

    if command -v sensors &>/dev/null; then
        run_cmd "$LOG_FILE" timeout 5s sensors >> "$LOG_FILE" 2>&1 || true
        # 온도가 설정 임계치 이상이면 경고
        local high_temp
        high_temp=$(sensors | awk '/°C/ { if ($2+0 > '$TEMP_THRESHOLD') print $2 }')
        if [ -n "$high_temp" ]; then
            send_alert "High Temperature" "Detected high system temperature(s): $high_temp. Check cooling system." "WARN" "check_system_temperature ($LOG_FILE)"
        fi
    else
        log "⚠️ 'sensors' command not found. Install lm-sensors for temperature monitoring." "$LOG_FILE"
        send_alert "Missing Temperature Monitoring" "lm-sensors package is not installed. Install it with 'apt-get install lm-sensors' for temperature monitoring." "WARN" "check_system_temperature ($LOG_FILE)"
    fi
}


### [9] 시스템 로그 분석 ############################################
# journalctl과 /var/log/auth.log를 분석하여 심각한 시스템 이벤트 및 보안 이슈를 확인합니다.
# 예: kernel panic, OOM, SSH 로그인 실패 등. 문제가 발견되면 WARN 또는 CRIT 알림을 발송합니다.
analyze_system_logs() {
    local LOG_FILE="$LOG_BASE/sys_events_$(date +%F).log"
    log "====== analyze_system_logs ======" "$LOG_FILE"

    local KEYWORDS="watchdog|kernel|panic|oom|fail|error|usb|network|segfault|NMI|denied|violation|attack|suspicious"
           
    # 설정 변수 로드 (기본값 포함)
    local fail_time_range="${SSH_FAIL_TIME_RANGE:-2 hour ago}"
    local warn_threshold="${SSH_FAIL_WARN_COUNT:-10}"
    local block_threshold="${SSH_BLOCK_THRESHOLD:-30}"

    # 시스템 이벤트 로그 분석
    run_cmd "$LOG_FILE" journalctl -p 0..3 -n 1000 --since "$fail_time_range" | grep -Ei "$KEYWORDS" >> "$LOG_FILE" || true
    
    # 인증 로그 분석 (로그인 실패 및 보안 이벤트)
    log "--- Auth Log Analysis ---" "$LOG_FILE"
 
    local auth_file="$(detect_auth_log_file)" ######## sim-test
    if [ -n "$auth_file" ]; then
        log "Checking SSH login failures in $auth_file" "$LOG_FILE"
        run_cmd "$LOG_FILE" grep -i "Failed password" "$auth_file" | tail -50 >> "$LOG_FILE" || true
    elif command -v journalctl &>/dev/null; then
        log "Using journalctl for SSH failure log parsing" "$LOG_FILE"
        run_cmd "$LOG_FILE" journalctl -u sshd --since "1 hour ago" | grep -i "Failed password" | tail -50 >> "$LOG_FILE" || true
    else
        log "No auth log or journalctl found. Cannot check SSH login failures." "$LOG_FILE"
    fi

    # ========= SSH 보안 모니터링 및 강화 (enhance_ssh_security 함수를 통합) =========
    # SSH 실패 시도 수 계산
    local ssh_failures=0
    ssh_failures=$(journalctl -u sshd --since "$fail_time_range" | grep -c "Failed password" || echo 0)

    # SSH 공격 분석
    if [ "$ssh_failures" -ge "$warn_threshold" ]; then
        log "--- SSH Security Monitoring ---" "$LOG_FILE"

        local attack_ips
        attack_ips=$(journalctl -u sshd --since "$fail_time_range" | grep "Failed password" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -10)

        local msg="Detected $ssh_failures failed SSH login attempts in the past $fail_time_range."
        if [ -n "$attack_ips" ]; then
            msg+="\n\nTop attacking IPs:"
            # while read -r count ip; do
            #     ip_info=$(get_ip_info "$ip")
            #     msg+="\n  $count $ip  $ip_info"
            # done <<< "$attack_ips"
            while read -r count ip; do
                msg+="\n  $count  $ip"
            done <<< "$attack_ips"
        fi
        send_alert "SSH Brute Force" "$msg" "WARN" "analyze_system_logs ($LOG_FILE)"


        # 과도한 시도 IP에 대한 차단 
        # (SSH_FAIL_TIME_RANGE 시간동안, 누적된 로그인 실패 횟수가 SSH_BLOCK_THRESHOLD를 초과하면 iptables를 통해 영구 차단)
        local blocked_summary=""
        blocked_ips=$(echo "$attack_ips" | awk -v threshold="$block_threshold" '$1 >= threshold {print $2}')
        if [ -n "$blocked_ips" ]; then
            while read -r ip; do
                if ! iptables-save | grep -q "\-A INPUT -s $ip/32 -j DROP"; then
                    iptables -I INPUT -s "$ip" -j DROP
                    blocked_summary+="$ip (manually banned, permanent)\n"
                fi
            done <<< "$blocked_ips"

            if [ -n "$blocked_summary" ]; then
                send_alert "Permanent IP Block" \
                    "Blocked the following IPs for exceeding threshold ($block_threshold failures in last $fail_time_range):\n$blocked_summary" \
                    "WARN" "analyze_system_logs ($LOG_FILE)"
            fi

            if [ -n "$blocked_summary" ] || [ -n "$new_ips" ]; then
                local summary_msg="Summary of IPs blocked in the last $fail_time_range:\n"
                summary_msg+="\n🔒 fail2ban blocks:"
                while read -r ip; do
                    [ -z "$ip" ] && continue
                    # ip_info=$(get_ip_info "$ip")
                    # summary_msg+="\n- $ip  $ip_info"
                    summary_msg+="\n- $ip"
                done <<< "$new_ips"

                summary_msg+="\n\n🛡️ script blocks:\n$blocked_summary"
                send_alert "Recent IP Blocks ($fail_time_range)" "$summary_msg" "INFO" "analyze_system_logs ($LOG_FILE)"
            fi
        fi
    else
        log "✅ SSH login failures within normal range: $ssh_failures (threshold: $warn_threshold)" "$LOG_FILE"
    fi

    # Fail2ban 설치 및 상태 확인
    if ! command -v fail2ban-client &>/dev/null; then
        log "⚠️ fail2ban not installed. Consider installing it to protect against brute force attacks." "$LOG_FILE"
        send_alert "Security Recommendation" "fail2ban is not installed. This can help protect against the detected SSH brute force attacks." "WARN" "analyze_system_logs"
    else
        log "✅ fail2ban is installed" "$LOG_FILE"
        run_cmd "$LOG_FILE" fail2ban-client status sshd || true
    fi
    
    # SSH 설정 보안 권장사항 제공
    log "--- SSH Security Recommendations ---" "$LOG_FILE"
    local recommendations=(
        "PermitRootLogin no"
        "PasswordAuthentication no"
        "MaxAuthTries 3"
        "UsePAM yes"
    )
    
    for rec in "${recommendations[@]}"; do
        local setting=$(echo "$rec" | cut -d' ' -f1)
        local value=$(echo "$rec" | cut -d' ' -f2)
        if ! grep -q "^$setting $value" /etc/ssh/sshd_config; then
            log "⚠️ Recommended: Set '$setting $value' in /etc/ssh/sshd_config" "$LOG_FILE"
        else
            log "✅ Good: '$setting $value' is already set" "$LOG_FILE"
        fi
    done

    # OOM 킬러 발생 확인
    if grep -q "Out of memory" "$LOG_FILE"; then
        send_alert "OOM Killer" "Out of Memory killer was triggered. Immediate attention required." "CRIT" "analyze_system_logs ($LOG_FILE)"
    fi
}

### [10] 좀비 프로세스 감시 #########################################
# 좀비 프로세스 수가
# - WARN 임계치 초과 시: 알림 + 로그
# - KILL 임계치 초과 시: 부모 PID에 SIGCHLD + 컨테이너별 재시작

# - 좀비 프로세스 및 해당 부모 프로세스의 상세 정보를 기록하고,
# - 부모 프로세스에 SIGCHLD 신호를 보내 좀비 프로세스 정리를 시도하며 WARN 알림을 발송합니다.
manage_zombie_processes() {
    get_docker_container_name_by_pid() {
        local pid="$1"
        local cid=""
        local cname=""

        # 도커 컨테이너 ID 추출
        cid=$(cat /proc/"$pid"/cgroup 2>/dev/null | grep 'docker' | head -1 | awk -F/ '{print $3}')
        if [ -n "$cid" ]; then
            # 컨테이너 이름 조회
            cname=$(docker ps --no-trunc --format '{{.ID}} {{.Names}}' | grep "$cid" | awk '{print $2}')
            echo "$cname"
        else
            echo ""
        fi
    }

    get_k8s_pod_name_by_pid() {
        local pid="$1"
        local pod=""
        # 쿠버네티스 cgroup 경로 추출 예시: /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podXXXXXXX.slice/cri-containerd-XXXXXXX.scope
        local cg_path
        cg_path=$(cat /proc/"$pid"/cgroup 2>/dev/null | grep 'kubepods' | head -1)
        if [[ "$cg_path" =~ pod([a-f0-9\-]+) ]]; then
            local pod_uid="${BASH_REMATCH[1]}"
            pod=$(kubectl get pod -A --no-headers --field-selector=status.phase=Running -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid' | grep "$pod_uid" | awk '{print $2}')
            echo "$pod"
        else
            echo ""
        fi
    }

    get_container_name_by_containerd() {
        local pid="$1"
        local cg_path cid name crictl_cmd

        # crictl 경로 확인
        if command -v crictl &>/dev/null; then
            crictl_cmd="crictl"
        elif [ -x "/usr/local/bin/crictl" ]; then
            crictl_cmd="/usr/local/bin/crictl"
        else
            echo "crictl_not_found"
            return
        fi

        # CGroup에서 containerd 기반 컨테이너 ID 추출
        cg_path=$(cat /proc/"$pid"/cgroup 2>/dev/null | grep -E 'cri-containerd|containerd' | head -1)
        if [[ "$cg_path" =~ ([a-f0-9]{64}) ]]; then
            cid="${BASH_REMATCH[1]}"
            # container ID가 정확히 일치하는 항목 찾기
            name=$($crictl_cmd ps -a --quiet | grep "$cid" | while read full_id; do
                $crictl_cmd inspect "$full_id" 2>/dev/null | grep -m1 '"name":' | awk -F'"' '{print $4}'
            done)
            echo "$name"
        else
            echo ""
        fi
    }
    
    auto_cleanup_zombies() {
        log "→ Running auto_cleanup_zombies" "$LOG_FILE"
        for ppid in $(ps -eo ppid,stat | awk '$2=="Z" {print $1}' | sort -u); do
            run_cmd "$LOG_FILE" ps -p "$ppid" -o cmd= | grep -qE "(systemd|init|sshd)" && continue
            log "→ Sending SIGCHLD to parent PID $ppid to trigger zombie collection" "$LOG_FILE"
            run_cmd "$LOG_FILE" kill -SIGCHLD "$ppid"
        done
    }

    # 좀비 프로세스 정보를 수집하는 함수
    get_zombie_details() {
        local zombie_info=""
        
        while IFS= read -r line; do
            local pid=$(echo "$line" | awk '{print $1}')
            local ppid=$(echo "$line" | awk '{print $2}')
            local cmd=$(echo "$line" | cut -d' ' -f4-)
            
            # 컨테이너/파드 정보 확인
            local cname
            cname=$(get_docker_container_name_by_pid "$ppid")
            
            if [ -z "$cname" ]; then
                cname=$(get_k8s_pod_name_by_pid "$ppid")
            fi
            if [ -z "$cname" ]; then
                cname=$(get_container_name_by_containerd "$ppid")
            fi
            
            # 상세 정보 구성
            zombie_info+="PID: $pid, PPID: $ppid\n"
            zombie_info+="Command: $cmd\n"
            if [ -n "$cname" ]; then
                zombie_info+="Container/Pod: $cname\n"
            fi
            zombie_info+="----------------------------------------\n"
            
        done < <(ps -eo pid,ppid,stat,cmd | awk '$3 ~ /Z/')
        
        echo -e "$zombie_info"
    }


    monitor_zombie_sources() {
        local threshold=5
        local recent_zombie_log="$LOG_BASE/zombie_sources_recent.log"
        local report=""

        ps -eo ppid,stat | awk '$2=="Z" {print $1}' | sort | uniq -c | while read count ppid; do
            if [ "$count" -ge "$threshold" ]; then
                cmd=$(ps -p "$ppid" -o cmd= 2>/dev/null)
                report+="↪ PPID $ppid (cmd: $cmd) has spawned $count zombies\n"
            fi
        done

        if [ -n "$report" ]; then
            log "→ Detected potential zombie sources:\n$report" "$LOG_FILE"
            send_alert "Zombie Parent Watch" "Repeated zombie sources detected:\n$report" "WARN" "manage_zombie_processes ($LOG_FILE)"
        fi
    }

    # auto_cleanup_zombies()는 2093-2100줄에 이미 정의됨 (중복 제거)

    local LOG_FILE="$LOG_BASE/zombie_proc_$(date +%F).log"
    log "====== manage_zombie_processes ======" "$LOG_FILE"

    # 좀비 프로세스 수 확인
    local zombie_count=0
    zombie_count=$(ps -eo stat | grep -c '^Z') || true
    log "→ Found $zombie_count zombie processes" "$LOG_FILE"

    auto_cleanup_zombies
    declare -A container_zombie_count
    declare -A container_ppids

    if [ "$zombie_count" -ge "$ZOMBIE_WARN_THRESHOLD" ]; then
        local zombie_summary=""
        local zombie_details=$(get_zombie_details)
        
        # 컨테이너별 좀비 프로세스 카운트
        while IFS= read -r line; do
            local pid ppid stat cmd
            read pid ppid stat cmd <<< "$line"
            
            local cname
            cname=$(get_docker_container_name_by_pid "$ppid")
            if [ -z "$cname" ]; then
                cname=$(get_k8s_pod_name_by_pid "$ppid")
            fi
            if [ -z "$cname" ]; then
                cname=$(get_container_name_by_containerd "$ppid")
            fi

            if [ -n "$cname" ]; then
                ((container_zombie_count["$cname"]++))
                container_ppids["$cname"]+="$ppid "
                zombie_summary+="Zombie PID $pid (parent: $ppid, container/pod: $cname)\n"
            else
                zombie_summary+="Zombie PID $pid (parent: $ppid, no container/pod)\n"
            fi

            # 자동 정리 시도
            log "→ Attempting SIGCHLD to parent $ppid to clean up zombie PID $pid" "$LOG_FILE"
            kill -s SIGCHLD "$ppid" 2>/dev/null
            sleep 1

            # 여전히 좀비인 경우 부모 프로세스 종료 시도
            if ps -p "$pid" -o stat= | grep -q '^Z'; then
                parent_cmd=$(ps -p "$ppid" -o cmd=)
                if ! echo "$parent_cmd" | grep -qE "(systemd|init|sshd)"; then
                    log "⚠️ Zombie still present. Attempting to kill parent $ppid ($parent_cmd)" "$LOG_FILE"
                    kill -TERM "$ppid" 2>/dev/null
                    sleep 1
                    if kill -0 "$ppid" 2>/dev/null; then
                        log "→ TERM failed. Forcing KILL on parent $ppid" "$LOG_FILE"
                        kill -KILL "$ppid"
                    fi
                fi
            fi
        done < <(ps -eo pid,ppid,stat,cmd | awk '$3 ~ /Z/')

        # 알림 전송
        send_alert "Zombie Processes" \
            "High number of zombie processes: $zombie_count\n\n$zombie_summary\n\nDetailed Information:\n$zombie_details" \
            "WARN" \
            "manage_zombie_processes ($LOG_FILE)"
    fi

    monitor_zombie_sources
    if [ "$zombie_count" -ge "$ZOMBIE_KILL_THRESHOLD" ]; then
        log "→ Zombie count exceeds kill threshold ($ZOMBIE_KILL_THRESHOLD), initiating cleanup" "$LOG_FILE"
        
        # SIGCHLD로 정리 시도
        for ppid in $(ps -eo ppid,stat | awk '$2=="Z" {print $1}' | sort -u); do
            run_cmd "$LOG_FILE" ps -p "$ppid" -o cmd= | grep -qE "(systemd|init|sshd)" && continue
            log "→ Sending SIGCHLD to zombie parent PID $ppid" "$LOG_FILE"
            run_cmd "$LOG_FILE" kill -SIGCHLD "$ppid"
        done

        # 컨테이너 재시작 (좀비가 많은 컨테이너만)
        for cname in "${!container_zombie_count[@]}"; do
            local count=${container_zombie_count["$cname"]}
            if [ "$count" -ge "$ZOMBIE_KILL_THRESHOLD" ]; then
                log "→ Checking restart policy for container $cname" "$LOG_FILE"
                # local restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cname" 2>/dev/null)
                local restart_policy=$(timeout 5s docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cname" 2>/dev/null || echo "")
                timeout 10s docker restart "$cname" >> "$LOG_FILE" 2>&1 && send_alert "Zombie Cleanup" "Restarted container $cname due to $count zombie processes" "INFO" "manage_zombie_processes ($LOG_FILE)"
                log "→ Restart policy for $cname: $restart_policy" "$LOG_FILE"

                if [ "$restart_policy" = "" ] || [ "$restart_policy" = "no" ]; then
                    log "→ WARNING: Container $cname has no auto-restart policy!" "$LOG_FILE"
                    send_alert "Container Restart Policy" "Container $cname has no restart policy but was restarted due to zombie overflow." "WARN" "manage_zombie_processes ($LOG_FILE)"
                fi

                log "→ Restarting container $cname (zombie count: $count)" "$LOG_FILE"
                docker restart "$cname" >> "$LOG_FILE" 2>&1 && \
                    send_alert "Zombie Cleanup" "Restarted container $cname due to $count zombie processes" "INFO" "manage_zombie_processes ($LOG_FILE)"
            fi
        done
    fi
}

### [12] 서버 자가 복구 스크립트 ###################################
# 자동 복구 기능은 ENABLE_SELF_HEALING이 true로 설정된 경우에만 실행합니다.
# 임시 파일 정리, 실패한 서비스 재시작, 크래시 덤프 및 세션 정리 등을 시도합니다.
server_self_healing() {
    if [ "$ENABLE_SELF_HEALING" != true ]; then
        return
    fi
    local LOG_FILE="$LOG_BASE/self_healing_$(date +%F).log"
    log "====== server_self_healing ======" "$LOG_FILE"
    
    # 오래된 임시 파일 정리
    log "--- 임시 파일 정리 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" find /tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # 실패한 systemd 서비스 재시작 시도
    log "--- 실패한 서비스 복구 ---" "$LOG_FILE"
    for failed_unit in $(systemctl --failed --plain --no-legend | awk '{print $1}'); do
        # 중요한 서비스는 제외
        if echo "$failed_unit" | grep -qE "(network|sshd|firewalld)"; then
            log "→ 중요 서비스 $failed_unit 는 수동 확인 필요" "$LOG_FILE"
            send_alert "Critical Service Failed" "Critical service $failed_unit has failed and requires manual intervention" "CRIT" "server_self_healing ($LOG_FILE)"
            continue
        fi
        
        log "→ 실패한 서비스 $failed_unit 재시작 시도" "$LOG_FILE"
        run_cmd "$LOG_FILE" timeout 5s systemctl restart "$failed_unit"

        # 재시작 성공 여부 확인
        if systemctl is-active --quiet "$failed_unit"; then
            log "✅ 서비스 $failed_unit 복구 성공" "$LOG_FILE"
            send_alert "Service Recovery" "Successfully recovered failed service: $failed_unit" "INFO" "server_self_healing ($LOG_FILE)"
        else
            log "❌ 서비스 $failed_unit 복구 실패" "$LOG_FILE"
            send_alert "Service Recovery Failed" "Failed to recover service: $failed_unit" "WARN" "server_self_healing ($LOG_FILE)"
        fi
    done
    
    # 이전 크래시 덤프 정리
    if [ -d "/var/crash" ]; then
        log "--- 크래시 덤프 정리 ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" find /var/crash -type f -mtime +7 -delete 2>/dev/null || true
    fi
    
    # 좀비 세션 정리
    log "--- 좀비 세션 정리 ---" "$LOG_FILE"
    for zombie_session in $(loginctl list-sessions --no-legend | awk '$1 !~ /^[0-9]+$/ {print $1}'); do
        log "→ 좀비 세션 $zombie_session 제거" "$LOG_FILE"
        run_cmd "$LOG_FILE" loginctl terminate-session "$zombie_session" >> "$LOG_FILE" 2>&1 || true
    done
    
    # 파일 시스템 체크 설정 (마운트 횟수 초과 시 체크하도록)
    log "--- 파일시스템 체크 설정 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" tune2fs -l $(findmnt -no SOURCE / 2>/dev/null) 2>/dev/null | grep -E 'Mount count|Maximum mount' >> "$LOG_FILE" || true
}


### [13] 도커 컨테이너 로그 분석 ###################################
# 도커 컨테이너의 로그를 분석하여, 최근 오류 및 경고, 재시작 횟수 등을 확인합니다.
# 일정 오류 빈도나 재시작 횟수가 감지되면 WARN 알림을 발송합니다.
analyze_container_logs() {
    local LOG_FILE="$LOG_BASE/container_logs_$(date +%F).log"
    log "====== analyze_container_logs ======" "$LOG_FILE"

    local RESTART_TRACK_FILE="$LOG_BASE/.container_restart_count"
    local ERROR_TRACK_FILE="$LOG_BASE/.container_error_count"
    touch "$RESTART_TRACK_FILE" "$ERROR_TRACK_FILE"
    
    # 컨테이너 관리 시스템 자동 감지
    local use_docker=false
    local use_kubernetes=false
    
    # Docker 활성화 체크 (단순하게)
    if command -v docker &>/dev/null; then
        if systemctl is-active --quiet docker 2>/dev/null; then
            use_docker=true
            log "✅ Docker is active and will be used for container analysis" "$LOG_FILE"
        else
            log "ℹ️ Docker is installed but not active" "$LOG_FILE"
        fi
    fi
    
    # Kubernetes 체크 (매우 단순하게 - kubectl 명령어 존재 여부만으로 판단)
    if command -v kubectl &>/dev/null; then
        use_kubernetes=true
        log "✅ kubectl command is available - will use Kubernetes for container analysis" "$LOG_FILE"
    else
        log "ℹ️ kubectl command not found" "$LOG_FILE"
    fi
    
    # Docker가 활성화되어 있는 경우 Docker 컨테이너 분석
    if [ "$use_docker" = true ]; then
        log "--- Docker Container Analysis ---" "$LOG_FILE"
        # Docker 컨테이너 분석 로직...
        # 실행 중인 컨테이너 목록
        docker ps --format "{{.Names}}" 2>/dev/null | while read container; do
            log "-- 컨테이너 로그 분석: $container ------" "$LOG_FILE"
            
            # 오류 및 경고 로그 추출 (타임아웃 강제 종료 포함 + 실패 허용)
            if ! timeout --signal=SIGKILL 30s docker logs --tail 100 "$container" 2>&1 | \
               grep -iE "error|warn|exception|fail|fatal" | tail -10 >> "$LOG_FILE"; then
                log "⚠️ Timeout or error getting logs for $container (tail 100)" "$LOG_FILE"
            fi

            # 오류 빈도 확인 (tail 1000)
            local error_count
            error_count=$(timeout --signal=SIGKILL 10s docker logs --tail 1000 "$container" 2>&1 | \
                grep -icE "error|exception|fatal" 2>/dev/null)
            error_count=${error_count:-0}

            # 이전 에러 수 불러오기 및 증가량 계산
            local prev_error_count error_delta
            prev_error_count=$(grep "^$container:" "$ERROR_TRACK_FILE" | cut -d: -f2)
            prev_error_count=${prev_error_count:-0}
            error_delta=$((error_count - prev_error_count))

            grep -v "^$container:" "$ERROR_TRACK_FILE" > "${ERROR_TRACK_FILE}.tmp"
            echo "$container:$error_count" >> "${ERROR_TRACK_FILE}.tmp"
            mv "${ERROR_TRACK_FILE}.tmp" "$ERROR_TRACK_FILE"

            #  컨테이너 오류 증가량 추적: 최근 1000줄 로그의 에러 수가 이전보다 50 이상 증가했을 때만 알림 전송.
            if [[ "$error_delta" -ge 50 ]]; then
                send_alert "Container Error Spike" \
                    "Container $container's error count increased by $error_delta (was $prev_error_count → now $error_count)" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi

            # 재시작 수 확인 및 변화 감지
            local restart_count prev_count delta
            restart_count=$(docker inspect "$container" --format '{{.RestartCount}}' 2>/dev/null)
            restart_count=${restart_count:-0}
            prev_count=$(grep "^$container:" "$RESTART_TRACK_FILE" | cut -d: -f2)
            prev_count=${prev_count:-0}
            delta=$((restart_count - prev_count))

            # 업데이트 기록
            grep -v "^$container:" "$RESTART_TRACK_FILE" > "${RESTART_TRACK_FILE}.tmp"
            echo "$container:$restart_count" >> "${RESTART_TRACK_FILE}.tmp"
            mv "${RESTART_TRACK_FILE}.tmp" "$RESTART_TRACK_FILE"

            # 조건: 이전보다 50 이상 증가한 경우에만 알림 (즉시 재시작 반복은 무시)
            if [ "$delta" -ge 50 ]; then
                send_alert "Container Restart Increased" \
                    "Container $container restart count increased by $delta (was $prev_count → now $restart_count)" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi
        done
    fi
    
    # Kubernetes가 활성화되어 있는 경우 Kubernetes Pod 분석
    if [ "$use_kubernetes" = true ]; then
        log "--- Kubernetes Pod Analysis ---" "$LOG_FILE"
        
        # 네임스페이스 목록 가져오기 (오류 무시)
        local namespaces
        namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "default")
        
        # 각 네임스페이스에서 파드 검색
        for ns in $namespaces; do
            log "Checking pods in namespace: $ns" "$LOG_FILE"
            
            # 파드 목록 가져오기 (오류 무시하고 계속 진행)
            local pods
            pods=$(kubectl get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
            
            # 파드가 있으면 분석
            if [ -n "$pods" ]; then
                for pod in $pods; do
                    log "-- Pod 로그 분석: $ns/$pod ------" "$LOG_FILE"
                    
                    # 컨테이너 목록 가져오기
                    local containers
                    containers=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null)
                    
                    # 컨테이너가 있으면 각 컨테이너 로그 분석
                    if [ -n "$containers" ]; then
                        for container in $containers; do
                            log "---- Container in pod: $container ----" "$LOG_FILE"
                            
                            # 오류 및 경고 로그 추출 (실패 무시)
                            kubectl logs --tail 100 "$pod" -c "$container" -n "$ns" 2>/dev/null | \
                                grep -iE "error|warn|exception|fail|fatal" | tail -10 >> "$LOG_FILE" || true
                            
                            # 오류 빈도 확인
                            local error_count=0
                            error_count=$(kubectl logs --tail 1000 "$pod" -c "$container" -n "$ns" 2>/dev/null | \
                                grep -icE "error|exception|fatal" || echo 0)
                            
                            # 이전 에러 수 불러오기 및 증가량 계산
                            local pod_key="$ns/$pod/$container"
                            local prev_error_count=0
                            prev_error_count=$(grep "^$pod_key:" "$ERROR_TRACK_FILE" | cut -d: -f2 || echo 0)
                            local error_delta=$((error_count - prev_error_count))
                            
                            # 기록 업데이트
                            grep -v "^$pod_key:" "$ERROR_TRACK_FILE" > "${ERROR_TRACK_FILE}.tmp" || true
                            echo "$pod_key:$error_count" >> "${ERROR_TRACK_FILE}.tmp"
                            mv "${ERROR_TRACK_FILE}.tmp" "$ERROR_TRACK_FILE"
                            
                            # 오류 증가 시 알림
                            if [[ "$error_delta" -ge 50 ]]; then
                                send_alert "Pod Error Spike" \
                                    "Pod $ns/$pod container $container error count increased by $error_delta (was $prev_error_count → now $error_count)" \
                                    "WARN" "analyze_container_logs ($LOG_FILE)"
                            fi
                        done
                        
                        # 재시작 수 확인
                        local restart_count=0
                        restart_count=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)
                        
                        # 이전 재시작 수 불러오기 및 변화 감지
                        local pod_key="$ns/$pod"
                        local prev_count=0
                        prev_count=$(grep "^$pod_key:" "$RESTART_TRACK_FILE" | cut -d: -f2 || echo 0)
                        local delta=$((restart_count - prev_count))
                        
                        # 업데이트 기록
                        grep -v "^$pod_key:" "$RESTART_TRACK_FILE" > "${RESTART_TRACK_FILE}.tmp" || true
                        echo "$pod_key:$restart_count" >> "${RESTART_TRACK_FILE}.tmp"
                        mv "${RESTART_TRACK_FILE}.tmp" "$RESTART_TRACK_FILE"
                        
                        # 재시작 카운트 증가 시 알림
                        if [ "$delta" -ge 50 ]; then
                            send_alert "Pod Restart Increased" \
                                "Pod $ns/$pod restart count increased by $delta (was $prev_count → now $restart_count)" \
                                "WARN" "analyze_container_logs ($LOG_FILE)"
                        fi
                    else
                        log "⚠️ No containers found in pod $ns/$pod" "$LOG_FILE"
                    fi
                done
            else
                log "ℹ️ No pods found in namespace $ns" "$LOG_FILE"
            fi
        done
    fi
    
    # 어떤 컨테이너 관리 시스템도 사용할 수 없는 경우
    if [ "$use_docker" = false ] && [ "$use_kubernetes" = false ]; then
        log "❌ Neither Docker nor Kubernetes are available for container monitoring" "$LOG_FILE"
        send_alert "Container Monitoring Unavailable" "No container runtime systems (Docker or Kubernetes) were detected" "WARN" "analyze_container_logs"
    fi
}


### [14] 히스토리 백업
backup_bash_history() {
    local LOG_FILE="$LOG_BASE/history_backup_$(date +%F).log"
    log "====== backup_bash_history ======" "$LOG_FILE"

    local now_ts
    now_ts=$(date '+%F_%H%M%S')

    local users=("root")

    # 기본 user 탐색: /home 아래에 있는 디렉토리 기준
    for home_dir in /home/*; do
        [ -d "$home_dir" ] || continue
        user_name=$(basename "$home_dir")
        users+=("$user_name")
    done

    for u in "${users[@]}"; do
        local home_dir
        [ "$u" == "root" ] && home_dir="/root" || home_dir="/home/$u"

        local hist_file="$home_dir/.bash_history"
        local backup_file="$home_dir/.bash_history.bak.$now_ts"

        if [ -f "$hist_file" ]; then
            cp "$hist_file" "$backup_file" 2>> "$LOG_FILE" && \
            log "→ Backed up $hist_file to $backup_file" "$LOG_FILE"
        else
            log "⚠️ History file not found: $hist_file" "$LOG_FILE"
        fi
    done
}



### [15] SSH 세션 이상 감지 #########################################
# SSH 연결 안정성 모니터링 (연결 끊김, 세션, 설정 문제 등에 집중)
monitor_ssh_stability() {
    local LOG_FILE="$LOG_BASE/ssh_stability_$(date +%F).log"
    log "====== monitor_ssh_stability ======" "$LOG_FILE"

    ## [1] SSH 연결 끊김 횟수 (최근 1시간)
    local disconnects=0
    
    # journalctl 사용 가능한 경우 (systemd 시스템)
    if command -v journalctl >/dev/null 2>&1 && is_systemd; then
        local journal_output=""
        if journal_output=$(timeout 10s journalctl -u ssh -u sshd --since "1 hour ago" --no-pager -q 2>/dev/null); then
            disconnects=$(echo "$journal_output" | grep -Ei "Connection closed|Disconnecting|session closed" | wc -l 2>/dev/null || echo 0)
        fi
    else
        local auth_log_file
        auth_log_file=$(detect_auth_log_file)
        if [[ -n "$auth_log_file" ]]; then
            local current_date=$(date '+%b %e')
            local current_date_alt=$(date '+%b  %e')
            disconnects=$(grep -Ei "Connection closed|Disconnecting|session closed" "$auth_log_file" 2>/dev/null | \
                grep -E "($current_date|$current_date_alt)" | wc -l 2>/dev/null || echo 0)
        fi
    fi
    
    # 숫자가 아닌 경우 0으로 설정
    if ! [[ "$disconnects" =~ ^[0-9]+$ ]]; then
        disconnects=0
    fi
    
    log "→ SSH disconnections (last 1h): $disconnects" "$LOG_FILE"

    # 너무 자주 끊긴다면 경고 (임계값을 환경변수로 설정 가능)
    if [[ "$disconnects" -ge "$SSH_DISCONNECT_THRESHOLD" ]]; then
        send_alert "Frequent SSH Disconnects" \
            "Detected $disconnects SSH disconnections in the past hour (threshold: $SSH_DISCONNECT_THRESHOLD). Check for instability or fail2ban issues." \
            "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi


    ## [2] 현재 로그인 세션 수
    local active_sessions=0
    
    # 여러 방법으로 세션 수 확인
    if command -v who >/dev/null 2>&1; then
        active_sessions=$(who 2>/dev/null | wc -l 2>/dev/null || echo 0)
    elif command -v w >/dev/null 2>&1; then
        active_sessions=$(w -h 2>/dev/null | wc -l 2>/dev/null || echo 0)
    elif [[ -r /proc/loadavg ]]; then
        # 최후의 수단: /proc에서 추정
        active_sessions=$(ps aux 2>/dev/null | grep -c '[s]shd:.*@' || echo 0)
    fi
    
    if ! [[ "$active_sessions" =~ ^[0-9]+$ ]]; then
        active_sessions=0
    fi
    
    log "→ Current active SSH sessions: $active_sessions" "$LOG_FILE"


    if [[ "$active_sessions" -gt "$SSH_SESSION_THRESHOLD" ]]; then
        send_alert "Too Many Active Sessions" \
            "There are $active_sessions active user sessions (threshold: $SSH_SESSION_THRESHOLD). Potential misuse or DoS attempt." \
            "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi


    ## [3] CLOSE_WAIT 세션 수 (소켓 누수 가능성)
    local close_wait_count=0
    
    if command -v ss >/dev/null 2>&1; then
        local ss_output=""
        if ss_output=$(timeout 10s ss -tan state close-wait 2>/dev/null); then
            close_wait_count=$(echo "$ss_output" | grep -c "CLOSE-WAIT" 2>/dev/null || echo 0)
        fi
    elif command -v netstat >/dev/null 2>&1; then
        local netstat_output=""
        if netstat_output=$(timeout 10s netstat -tan 2>/dev/null); then
            close_wait_count=$(echo "$netstat_output" | grep -c "CLOSE_WAIT" 2>/dev/null || echo 0)
        fi
    fi
    
    if ! [[ "$close_wait_count" =~ ^[0-9]+$ ]]; then
        close_wait_count=0
    fi
    
    log "→ Current CLOSE_WAIT sockets: $close_wait_count" "$LOG_FILE"
    
    if [[ "$close_wait_count" -gt "$CLOSE_WAIT_THRESHOLD" ]]; then
        send_alert "Excessive CLOSE_WAIT" \
            "Detected $close_wait_count CLOSE_WAIT sockets (threshold: $CLOSE_WAIT_THRESHOLD). Possible socket leak or stuck sessions." \
            "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi


    ## [4] SSH 설정 안정성 검사
    local ClientAliveInterval=0
    local ClientAliveCountMax=3
    local ssh_config
    ssh_config=$(detect_ssh_config)

    
    if [[ -n "$ssh_config" ]]; then
        # 설정값 읽기 (주석 제외, 대소문자 무시)
        ClientAliveInterval=$(grep -Ei "^[[:space:]]*ClientAliveInterval[[:space:]]" "$ssh_config" 2>/dev/null | \
            tail -1 | awk '{print $2}' 2>/dev/null || echo 0)
        ClientAliveCountMax=$(grep -Ei "^[[:space:]]*ClientAliveCountMax[[:space:]]" "$ssh_config" 2>/dev/null | \
            tail -1 | awk '{print $2}' 2>/dev/null || echo 3)
        
        # 숫자가 아닌 경우 기본값 설정
        if ! [[ "$ClientAliveInterval" =~ ^[0-9]+$ ]]; then
            ClientAliveInterval=0
        fi
        if ! [[ "$ClientAliveCountMax" =~ ^[0-9]+$ ]]; then
            ClientAliveCountMax=3
        fi
        
        log "→ SSH keepalive settings: ClientAliveInterval=$ClientAliveInterval, ClientAliveCountMax=$ClientAliveCountMax" "$LOG_FILE"
        
        if [[ "$ClientAliveInterval" -eq 0 ]] || [[ "$ClientAliveInterval" -gt "$SSH_MAX_INTERVAL" ]]; then
            send_alert "SSH Config Issue" \
                "SSH ClientAliveInterval is $ClientAliveInterval. Recommended: $SSH_RECOMMENDED_INTERVAL (to detect stale sessions early)." \
                "WARN" "monitor_ssh_stability ($LOG_FILE)"
        fi
    else
        log "⚠️ SSH config file not found or not readable" "$LOG_FILE"
    fi
    
    return 0
}

# SSH 보안 모니터링
monitor_ssh_security() {
    local LOG_FILE="$LOG_BASE/ssh_security_$(date +%F).log"
    log "====== monitor_ssh_security ======" "$LOG_FILE"

    # ========================
    # SSH 로그인 실패 시도 감지
    # ========================
    local recent_failures=0
    
    if command -v journalctl >/dev/null 2>&1 && is_systemd; then
        local journal_output=""
        if journal_output=$(timeout 15s journalctl -u ssh -u sshd --since "$SSH_FAIL_TIME_RANGE" --no-pager -q 2>/dev/null); then
            recent_failures=$(echo "$journal_output" | grep -c "Failed password\|Failed publickey\|Invalid user" 2>/dev/null || echo 0)
        fi
    else
        local auth_log_file
        auth_log_file=$(detect_auth_log_file)
        if [[ -n "$auth_log_file" ]]; then
            local time_filter=""
            if command -v date >/dev/null 2>&1; then
                local hour_ago=$(date -d '1 hour ago' '+%H' 2>/dev/null || date -v-1H '+%H' 2>/dev/null || echo "")
                local current_hour=$(date '+%H')
                time_filter="$hour_ago\|$current_hour"
            fi
            
            local log_content=""
            if [[ -n "$time_filter" ]]; then
                log_content=$(grep -E "($time_filter):[0-9]{2}:[0-9]{2}" "$auth_log_file" 2>/dev/null || cat "$auth_log_file" 2>/dev/null)
            else
                log_content=$(cat "$auth_log_file" 2>/dev/null)
            fi
            recent_failures=$(echo "$log_content" | grep -c "Failed password\|Failed publickey\|Invalid user" 2>/dev/null || echo 0)
        fi
    fi
    
    if ! [[ "$recent_failures" =~ ^[0-9]+$ ]]; then
        recent_failures=0
    fi
    
    log "→ Recent SSH login failures ($SSH_FAIL_TIME_RANGE): $recent_failures" "$LOG_FILE"

    # 경고 레벨 확인
    if [[ "$recent_failures" -ge "$SSH_FAIL_WARN_COUNT" ]]; then
        send_alert "SSH Login Warning" \
            "Detected $recent_failures failed SSH login attempts in the past $SSH_FAIL_TIME_RANGE.\nCheck for unusual activity." \
            "INFO" "monitor_ssh_security ($LOG_FILE)"
    fi

    # 브루트포스 공격 감지
    if [[ "$recent_failures" -ge "$SSH_BLOCK_THRESHOLD" ]]; then
        local auth_log_file
        auth_log_file=$(detect_auth_log_file)
        local attacking_ips=""
        
        if [[ -n "$auth_log_file" ]]; then
            attacking_ips=$(grep "Failed password\|Failed publickey\|Invalid user" "$auth_log_file" 2>/dev/null | \
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 || echo "")
        fi
        
        local ALERT_CACHE="/tmp/ssh_alert_cache.txt"
        touch "$ALERT_CACHE" 2>/dev/null || ALERT_CACHE="/dev/null"

        # 새로운 IP만 알림
        local new_ips=""
        while IFS=' ' read -r count ip; do
            [[ -z "$ip" || -z "$count" ]] && continue
            if ! grep -q "$ip" "$ALERT_CACHE" 2>/dev/null; then
                echo "$ip" >> "$ALERT_CACHE" 2>/dev/null
                new_ips+="$count $ip"$'\n'
            fi
        done <<< "$attacking_ips"

        if [[ -n "$(echo "$new_ips" | tr -d '[:space:]')" ]]; then
            local msg="Detected $recent_failures failed SSH login attempts in the past $SSH_FAIL_TIME_RANGE."
            msg+="\n\nTop new attacking IPs (threshold: $SSH_BLOCK_THRESHOLD):"
            while IFS=' ' read -r count ip; do
                [[ -z "$ip" || -z "$count" ]] && continue
                msg+="\n  $count  $ip"
            done <<< "$new_ips"

            send_alert "SSH Brute Force Attempt" "$msg" "WARN" "monitor_ssh_security ($LOG_FILE)"
        else
            log "→ All attacking IPs already alerted. Suppressing repeat alert." "$LOG_FILE"
        fi
    fi

    # ========================
    # Fail2Ban 상태 점검
    # ========================
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log "→ fail2ban is not installed" "$LOG_FILE"
        send_alert "Fail2Ban Missing" \
            "fail2ban이 설치되어 있지 않습니다. 서버 보안을 위해 설치를 권장합니다." \
            "INFO" "monitor_ssh_security ($LOG_FILE)"
        return 0
    fi

    log "--- Fail2Ban Status ---" "$LOG_FILE"
    
    # fail2ban 서비스 상태 확인
    local f2b_running=false
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            f2b_running=true
        fi
    elif command -v service >/dev/null 2>&1; then
        if service fail2ban status >/dev/null 2>&1; then
            f2b_running=true
        fi
    elif pgrep -f fail2ban >/dev/null 2>&1; then
        f2b_running=true
    fi
    
    if ! $f2b_running; then
        send_alert "Fail2Ban Not Running" \
            "fail2ban 서비스가 실행되지 않고 있습니다." \
            "WARN" "monitor_ssh_security ($LOG_FILE)"
        log "→ fail2ban service is not running" "$LOG_FILE"
        return 0
    fi
    
    # fail2ban jail 상태 확인
    local ssh_jail
    ssh_jail=$(detect_fail2ban_ssh_jail)
    
    if [[ -z "$ssh_jail" ]]; then
        log "→ No active SSH jails found in fail2ban" "$LOG_FILE"
        return 0
    fi
    
    log "→ Found active jail: $ssh_jail" "$LOG_FILE"
    
    local status_output=""
    if ! status_output=$(timeout 10s fail2ban-client status "$ssh_jail" 2>/dev/null); then
        log "→ Failed to get fail2ban status for jail: $ssh_jail" "$LOG_FILE"
        return 0
    fi
    
    echo "$status_output" >> "$LOG_FILE"

    # 차단된 IP 추출
    local banned_ips=""
    banned_ips=$(echo "$status_output" | grep 'Banned IP list:' | cut -d: -f2- | sed 's/^[[:space:]]*//' | tr -s ' ' || echo "")

    if [[ -n "$banned_ips" && "$banned_ips" != "None" ]]; then
        log "→ Currently Banned IP list: $banned_ips" "$LOG_FILE"

        # IP 목록 저장 및 새로운 IP 확인
        local banned_ips_file="/tmp/fail2ban_current_ips.txt"
        local banned_ips_old_file="/tmp/fail2ban_prev_ips.txt"

        echo "$banned_ips" | tr ' ' '\n' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | sort > "$banned_ips_file" 2>/dev/null || touch "$banned_ips_file"

        local new_ips=""
        if [[ -f "$banned_ips_old_file" ]]; then
            new_ips=$(comm -23 "$banned_ips_file" "$banned_ips_old_file" 2>/dev/null || echo "")
        else
            new_ips=$(cat "$banned_ips_file" 2>/dev/null || echo "")
        fi

        cp "$banned_ips_file" "$banned_ips_old_file" 2>/dev/null || true
            
        # 새로 차단된 IP가 있으면 알림
        if [[ -n "$(echo "$new_ips" | tr -d '[:space:]')" ]]; then
            local timestamp=$(date '+%F %T')
            echo "[$timestamp] Banned IPs: $banned_ips" >> "$LOG_BASE/fail2ban_ip_history.log" 2>/dev/null || true
            echo "Newly Banned IPs: $new_ips" >> "$LOG_FILE"

            local msg="Detected $recent_failures failed SSH login attempts in the past $SSH_FAIL_TIME_RANGE."
            msg+="\n\n🔒 Banned IPs by fail2ban (bantime: ${F2B_BANTIME}s):"

            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                msg+="\n- $ip"
            done <<< "$new_ips"

            send_alert "Fail2Ban Banned IPs" "$msg" "WARN" "monitor_ssh_security ($LOG_FILE)"
        fi
    else
        log "→ No currently banned IPs" "$LOG_FILE"
    fi

    # ========================
    # 반복 차단 IP 분석
    # ========================
    if [[ -f "$LOG_BASE/fail2ban_ip_history.log" ]]; then
        log "--- Repeat Offender Analysis ---" "$LOG_FILE"
        
        local stats_file="/tmp/fail2ban_stats.txt"
        if tail -n 1000 "$LOG_BASE/fail2ban_ip_history.log" 2>/dev/null | \
            grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 > "$stats_file" 2>/dev/null; then
            
            cat "$stats_file" >> "$LOG_FILE" 2>/dev/null || true

            while IFS=' ' read -r count ip; do
                [[ -z "$ip" || -z "$count" ]] && continue
                if [[ "$count" =~ ^[0-9]+$ ]] && [[ "$count" -ge 5 ]]; then
                    send_alert "Repeat Fail2Ban Offender" \
                        "IP $ip was banned $count times recently.\nConsider permanent blocking at firewall level." \
                        "WARN" "monitor_ssh_security ($LOG_FILE)"
                fi
            done < "$stats_file" 2>/dev/null || true
        fi
    fi
    
    # 추가 공격 IP 자동 차단 (함수가 있는 경우만)
    # ========================
    if declare -f auto_ban_attackers >/dev/null 2>&1; then
        auto_ban_attackers || true
    fi
    
    return 0
}



ban_ip_permanently() {
    local ip="$1"
    local LOG_FILE="$2"
    local PERMANENT_BAN_LIST="$LOG_BASE/etc/permanent_banned_ips.txt"
    mkdir -p "$(dirname "$PERMANENT_BAN_LIST")"
    touch "$PERMANENT_BAN_LIST"

    # 중복 체크 후 차단
    if grep -Fxq "$ip" "$PERMANENT_BAN_LIST"; then
        log "→ IP $ip already in permanent ban list." "$LOG_FILE"
        return 0
    fi

    echo "$ip" >> "$PERMANENT_BAN_LIST"

    # 정렬 및 중복 제거
    sort -u "$PERMANENT_BAN_LIST" -o "$PERMANENT_BAN_LIST"

    # 방화벽 차단
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' reject" || true
        firewall-cmd --reload || true
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -s "$ip" -j DROP || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    log "→ Permanently banned IP: $ip" "$LOG_FILE"
    # local ip_info=$(get_ip_info "$ip")  # 예: "BE Belgium / Proximus"
    # log "→ Permanently banned IP: $ip  $ip_info" "$LOG_FILE"
    
    send_alert "Permanent IP Ban" "🔐 Permanently banned IP:\n- $ip  $ip_info" "WARN" "ban_ip_permanently ($LOG_FILE)"
}


### 공격 IP 차단 : SSH 로그인 실패 로그를 분석하여 공격 IP를 ipset + iptables로 차단
auto_ban_attackers() {
    local LOG_FILE="$LOG_BASE/auto_ban_attackers_$(date +%F).log"
    local THRESHOLD="${SSH_BLOCK_THRESHOLD:-15}" # 실패 횟수 기준
    local IPSET_NAME="blacklist"
    local TMPFILE="$LOG_BASE/ssh_attack_ips.txt"

    # SSH 로그 파일 자동 선택
    if [ -f /var/log/secure ]; then
        LOGFILE="/var/log/secure"
    elif [ -f /var/log/auth.log ]; then
        LOGFILE="/var/log/auth.log"
    else
        echo "[!] No valid SSH log file found." >&2
        return 1
    fi

    # ipset 생성
    ipset list "$IPSET_NAME" > /dev/null 2>&1 || ipset create "$IPSET_NAME" hash:ip

    # 최근 6시간 이내 실패 시도 수집
    grep "Failed password" "$LOGFILE" | awk '{print $(NF-3)}' | \
        sort | uniq -c | sort -nr | \
        awk -v threshold="$THRESHOLD" '$1 >= threshold {print $2}' > "$TMPFILE"

    # IP 차단 추가
    while read -r ip; do
        if ! ipset test "$IPSET_NAME" "$ip" > /dev/null 2>&1; then
            local timestamp count msg

            timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

            # 누적 차단 로그에서 이 IP 등장 횟수 계산
            count=0
            if [[ -f "$LOG_FILE" ]]; then
                count=$(grep -c "$ip" "$LOG_FILE")
            fi

            # 메시지 구성: 날짜, IP, 누적 차단 수 포함
            msg="[$timestamp] [+] Blocking: $ip (fail count: $count)"
            
            log "--- Auto Ban Attackers ---" "$LOG_FILE"
            log "$msg" "$LOG_FILE"
            send_alert "Auto Ban Attackers" "$msg" "CRIT" "auto_ban_attackers ($LOG_FILE)"
            ipset add "$IPSET_NAME" "$ip"
        fi
    done < "$TMPFILE"

    # iptables 적용
    iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || \
    iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
}



# SSH 연결 최적화 및 자동 관리 함수
optimize_sshd_config() {
    local LOG_FILE="$LOG_BASE/ssh_optimize_config_$(date +%F).log"
    log "====== optimize_sshd_config ======" "$LOG_FILE"
    local ssh_config="/etc/ssh/sshd_config"
    local need_reload=false

    declare -A CONFIGS=(
        [ClientAliveInterval]=30
        [ClientAliveCountMax]=3
        [TCPKeepAlive]=yes
        [MaxStartups]='20:50:100'
        [LoginGraceTime]=30
    )

    for param in "${!CONFIGS[@]}"; do
        local val="${CONFIGS[$param]}"
        local cur_val=$(grep -E "^[[:space:]]*$param" "$ssh_config" | awk '{print $2}' || echo "")

        if [ "$cur_val" != "$val" ]; then
            if grep -q "^[[:space:]]*$param" "$ssh_config"; then
                sed -i "s/^[[:space:]]*$param.*/$param $val/" "$ssh_config"
            else
                echo "$param $val" >> "$ssh_config"
            fi
            need_reload=true
            log "→ $param updated: $cur_val → $val" "$LOG_FILE"
        fi
    done

    if [ "$need_reload" = true ]; then
        systemctl reload sshd
        send_alert "SSH Config Optimized" "sshd_config 최적 설정이 적용됨." "INFO" "optimize_sshd_config"
    fi
}

# === NEW: SSH 서비스 우선순위 조정만 수행 ===
prioritize_sshd_service() {
    local LOG_FILE="$LOG_BASE/ssh_priority_$(date +%F).log"
    log "====== prioritize_sshd_service ======" "$LOG_FILE"

    local pid=$(pgrep -f '^/usr/sbin/sshd' | head -1 || echo "")
    if [ -n "$pid" ]; then
        renice -10 "$pid" 2>/dev/null || true
        log "→ sshd PID $pid 우선순위 -10으로 설정됨" "$LOG_FILE"
    fi

    mkdir -p /etc/systemd/system/ssh.service.d || true
    cat << EOF > /etc/systemd/system/ssh.service.d/priority.conf || true
[Service]
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
IOSchedulingClass=realtime
IOSchedulingPriority=0
EOF
    systemctl daemon-reexec || true
    systemctl restart ssh || true
    send_alert "sshd 우선순위 적용" "sshd systemd 우선순위가 향상되었습니다." "INFO" "prioritize_sshd_service"
}

# 시스템 리소스 자동 관리 함수
manage_system_resources() {
    local LOG_FILE="$LOG_BASE/resource_manage_$(date +%F).log"
    log "====== manage_system_resources ======" "$LOG_FILE"
    
    # [1] 시스템 부하 확인
    local load_avg cpu_count load_threshold
    load_avg=$(awk '{print $1}' /proc/loadavg)
    cpu_count=$(nproc)
    load_threshold=$(echo "$cpu_count * 1.5" | bc)
    
    log "→ System load: $load_avg (CPU count: $cpu_count, threshold: $load_threshold)" "$LOG_FILE"
    
    # [2] 높은 부하 상태일 때 자동 조치
    if (( $(echo "$load_avg > $load_threshold" | bc -l) )); then
        log "→ System is under high load ($load_avg > $load_threshold)" "$LOG_FILE"
        send_alert "High System Load" "System load ($load_avg) exceeds threshold ($load_threshold)." "WARN" "manage_system_resources ($LOG_FILE)"
        
        # 상위 부하 프로세스 기록
        log "--- Top CPU Processes ---" "$LOG_FILE"
        ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu | head -10 >> "$LOG_FILE"
        
        # 자동 리소스 관리 (ENABLE_SELF_HEALING이 true일 경우)
        if [ "$ENABLE_SELF_HEALING" = true ]; then
            # 우선순위 조정 대상 프로세스 (화이트리스트 제외)
            for pid in $(ps -eo pid,pcpu --sort=-%cpu | awk 'NR>1 && $2>30 {print $1}' | head -5); do
                # 중요 프로세스 제외 (systemd, sshd, init 등)
                if ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init|kernel|bash)"; then
                    local current_nice
                    current_nice=$(ps -o nice= -p "$pid")
                    
                    if [ "$current_nice" -lt 10 ]; then
                        log "→ Lowering priority of PID $pid (current nice: $current_nice)" "$LOG_FILE"
                        renice +15 "$pid" >> "$LOG_FILE" 2>&1 || true
                        
                        # I/O 우선순위도 조정
                        if command -v ionice &> /dev/null; then
                            ionice -c 3 -p "$pid" >> "$LOG_FILE" 2>&1 || true
                            log "→ Set I/O class to idle for PID $pid" "$LOG_FILE"
                        fi
                    fi
                fi
            done
            
            # 커널 파라미터 최적화
            if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
                echo "vm.swappiness=10" >> /etc/sysctl.conf
                sysctl -w vm.swappiness=10 >> "$LOG_FILE" 2>&1 || true
                log "→ Set vm.swappiness=10 to reduce swap usage" "$LOG_FILE"
            fi
            
            # OOM 스코어 조정 (비중요 프로세스)
            for pid in $(ps -eo pid,pmem --sort=-%mem | awk 'NR>1 && $2>5 {print $1}' | head -5); do
                if ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init|kernel|bash)"; then
                    echo 500 > /proc/$pid/oom_score_adj 2>> "$LOG_FILE" || true
                    log "→ Increased OOM kill priority for PID $pid" "$LOG_FILE"
                fi
            done
        fi
    fi
    
    # [3] 메모리 사용량 확인 및 관리
    local mem_total mem_avail mem_percentage
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    mem_percentage=$(echo "scale=2; ($mem_total - $mem_avail) * 100 / $mem_total" | bc)
    
    log "→ Memory usage: ${mem_percentage}% (Available: ${mem_avail}MB / Total: ${mem_total}MB)" "$LOG_FILE"
    
    # 메모리 부족 시 조치
    if (( $(echo "$mem_percentage > 90" | bc -l) )); then
        send_alert "Low Memory Warning" "System memory usage is very high (${mem_percentage}%)." "WARN" "manage_system_resources ($LOG_FILE)"
        
        if [ "$ENABLE_SELF_HEALING" = true ]; then
            # 캐시 해제
            sync
            if [ -w "/proc/sys/vm/drop_caches" ]; then
                echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || log "Failed to drop caches" "$LOG_FILE"
            else
                log "No permission to drop caches" "$LOG_FILE"
            fi
            log "→ Dropped filesystem caches to free memory" "$LOG_FILE"
            
            # 스왑 공간 확보
            run_cmd "$LOG_FILE" swapoff -a && run_cmd "$LOG_FILE" swapon -a || true
            log "→ Cycled swap space to reduce fragmentation" "$LOG_FILE"
        fi
    fi
    
    # [4] 디스크 I/O 상태 확인
    if command -v iostat &> /dev/null; then
        log "--- Disk I/O Statistics ---" "$LOG_FILE"
        iostat -x 1 2 | grep -v "loop\|ram" >> "$LOG_FILE" 2>&1 || true
        
        # 높은 I/O 대기 감지
        local io_wait
        io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')
        
        if [ "$io_wait" -gt 30 ]; then
            send_alert "High I/O Wait" "System has high I/O wait time (${io_wait}%)." "WARN" "manage_system_resources ($LOG_FILE)"
            
            if [ "$ENABLE_SELF_HEALING" = true ] && command -v ionice &> /dev/null; then
                # 높은 I/O 사용 프로세스 찾기
                for pid in $(iotop -b -n 1 -o | head -n 10 | awk '{print $1}' | grep -E '[0-9]+'); do
                    if [ "$pid" -gt 1 ] && ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init)"; then
                        ionice -c 3 -p "$pid" >> "$LOG_FILE" 2>&1 || true
                        log "→ Set I/O class to idle for high I/O process PID $pid" "$LOG_FILE"
                    fi
                done
            fi
        fi
    fi
}


# === NEW: 자원 관리 리팩터링 ===
manage_high_load() {
    local LOG_FILE="$LOG_BASE/high_load_$(date +%F).log"
    log "====== manage_high_load ======" "$LOG_FILE"

    local load_avg=0 cpu_count=1 load_threshold=0
    
    load_avg=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
    cpu_count=$(nproc 2>/dev/null || echo "1")
    
    if command -v bc &>/dev/null; then
        load_threshold=$(echo "$cpu_count * 1.5" | bc -l 2>/dev/null || echo "$cpu_count")
    else
        load_threshold=$((cpu_count * 3 / 2))
    fi
    log "System load: $load_avg (CPU count: $cpu_count, dynamic threshold: $load_threshold, static warn: $LOAD_WARN_THRESHOLD)" "$LOG_FILE"

    local is_overloaded=0
    if command -v bc &>/dev/null; then
        is_overloaded=$(echo "$load_avg > $load_threshold" | bc -l 2>/dev/null || echo "0")
    else
        local load_int=${load_avg%.*}
        [ "$load_int" -gt "$load_threshold" ] && is_overloaded=1 || is_overloaded=0
    fi

    if [ "$is_overloaded" -eq 1 ]; then
        send_alert "High System Load" "System load ($load_avg) exceeds dynamic threshold ($load_threshold)." "WARN" "manage_high_load ($LOG_FILE)"

        log "--- Top CPU Processes ---" "$LOG_FILE"
        ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu 2>/dev/null | head -10 >> "$LOG_FILE" || true
    fi

    # 추가: 고정 임계값 초과 여부도 따로 체크
    if (( $(echo "$load_avg > $LOAD_WARN_THRESHOLD" | bc -l) )); then
        send_alert "Very High Load" "System load ($load_avg) exceeds static threshold ($LOAD_WARN_THRESHOLD)." "WARN" "manage_high_load ($LOG_FILE)"
    fi

    # Top CPU-consuming processes 기록
    log "--- Top CPU Processes ---" "$LOG_FILE"
    ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu 2>/dev/null | head -10 >> "$LOG_FILE" || true
}


manage_memory_pressure() {
    local LOG_FILE="$LOG_BASE/mem_pressure_$(date +%F).log"
    log "====== manage_memory_pressure ======" "$LOG_FILE"

    local mem_total mem_avail mem_percentage
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    mem_percentage=$(echo "scale=2; ($mem_total - $mem_avail) * 100 / $mem_total" | bc)

    log "Memory usage: ${mem_percentage}% (Available: ${mem_avail}MB / Total: ${mem_total}MB)" "$LOG_FILE"

    if (( $(echo "$mem_percentage > 90" | bc -l) )); then
        send_alert "Low Memory Warning" "System memory usage is very high (${mem_percentage}%)." "WARN" "manage_memory_pressure ($LOG_FILE)"

        sync && echo 3 > /proc/sys/vm/drop_caches 2>> "$LOG_FILE" || true
        log "→ Dropped filesystem caches to free memory" "$LOG_FILE"

        # swapoff -a && swapon -a >> "$LOG_FILE" 2>&1 || true
        run_cmd "$LOG_FILE" swapoff -a && run_cmd "$LOG_FILE" swapon -a || true
        log "→ Cycled swap space to reduce fragmentation" "$LOG_FILE"
    fi
}

manage_io_bottleneck() {
    local LOG_FILE="$LOG_BASE/io_bottleneck_$(date +%F).log"
    log "====== manage_io_bottleneck ======" "$LOG_FILE"

    if command -v iostat &> /dev/null; then
        iostat -x 1 2 | grep -v "loop\|ram" >> "$LOG_FILE" 2>&1 || true
        local io_wait
        io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')

        if [ "$io_wait" -gt 30 ]; then
            send_alert "High I/O Wait" "System has high I/O wait time (${io_wait}%)." "WARN" "manage_io_bottleneck ($LOG_FILE)"
        fi
    else
        send_alert "Missing iostat" "iostat command not found. Cannot monitor I/O wait." "WARN" "manage_io_bottleneck ($LOG_FILE)"
    fi
}

#  호환성을 위한 래퍼 함수
monitor_system_resources() {
    local LOG_FILE="$LOG_BASE/resource_monitor_$(date +%F).log"
    log "====== monitor_system_resources ======" "$LOG_FILE"
    log "→ Using refactored resource monitoring functions" "$LOG_FILE"
    
    manage_high_load
    manage_memory_pressure
    manage_io_bottleneck
}



### [17] 로그 정리 및 요약 #########################################
# 오래된 로그 파일을 정리(삭제 또는 압축)하고,
# 일일 요약 보고서를 생성하여 이메일로 전송할 수 있도록 합니다.
# ref. 압축 해제 : tar -zxvf logs_2025-03-28.tar.gz --strip-components=5
clean_old_logs() {
    local LOG_FILE="$LOG_BASE/log_cleanup_$(date +%F).log"
    log "====== clean_old_logs ======" "$LOG_FILE"
    # 필요한 디렉토리 확인 및 생성
    mkdir -p "$LOG_BASE" "$LOG_ARCHIVE_DIR" "$LOG_ALERTS_DIR" 2>/dev/null || true

    # [1] 로그 파일 압축 처리 : 오늘 날짜 파일은 제외하고, 파일 이름이 *_YYYY-MM-DD.log 인 로그 파일 압축
    local today=$(date +%F)
    local files_to_compress=()
    
    # 오늘 날짜가 아닌 로그 파일 찾기
    mapfile -t found_logs < <(find "$LOG_BASE" -maxdepth 1 -type f -name "*_*.log" ! -name "*.tar.gz" 2>/dev/null || true)
    
    for file in "${found_logs[@]}"; do
        # 파일이 실제로 존재하는지 확인
        [ -f "$file" ] || continue
        
        log_date=$(basename "$file" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || echo "")
        [[ "$log_date" == "$today" || -z "$log_date" ]] && continue
        files_to_compress+=("$file")
    done
    
    if [ ${#files_to_compress[@]} -eq 0 ]; then
        log "→ No past logs to compress." "$LOG_FILE"
    else
        # 날짜별로 파일 그룹화 및 압축
        local unique_dates
        unique_dates=$(printf '%s\n' "${files_to_compress[@]}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u)
        
        for date in $unique_dates; do
            log "--- Compressing logs for $date ---" "$LOG_FILE"
            local matched_files=()
            
            for f in "${files_to_compress[@]}"; do
                [[ "$f" =~ $date ]] && matched_files+=("$(basename "$f")")
            done
            
            if [ ${#matched_files[@]} -gt 0 ]; then
                pushd "$LOG_BASE" >/dev/null 2>&1 || continue
                
                # 압축 시도
                if tar -czf "$LOG_ARCHIVE_DIR/${date}_logs.tar.gz" "${matched_files[@]}" 2>/dev/null; then
                    # 원본 파일 삭제
                    for file in "${matched_files[@]}"; do
                        rm -f "$file" 2>/dev/null || true
                    done
                    log "→ Compressed ${#matched_files[@]} logs for $date" "$LOG_FILE"
                else
                    log "❌ Failed to compress logs for $date" "$LOG_FILE"
                fi
                
                popd >/dev/null 2>&1 || true
            fi
        done
    fi
    # [1-2] run_alerts/ 로그 별도 압축
    mapfile -t alert_logs < <(find "$LOG_ALERTS_DIR" -maxdepth 1 -type f -name "run_alerts_*.log" ! -name "*.tar.gz" 2>/dev/null || true)

    if [ ${#alert_logs[@]} -gt 0 ]; then
        local alert_dates
        alert_dates=$(printf '%s\n' "${alert_logs[@]}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | grep -v "$today" | sort -u)

        for date in $alert_dates; do
            log "--- Compressing run_alerts logs for $date ---" "$LOG_FILE"
            local matched_files=()

            for f in "${alert_logs[@]}"; do
                [[ "$f" =~ $date ]] && matched_files+=("$f")
            done

            if [ ${#matched_files[@]} -gt 0 ]; then
                local archive_name="$LOG_ARCHIVE_DIR/alerts_${date}.tar.gz"
                if tar -czf "$archive_name" "${matched_files[@]}" 2>/dev/null; then
                    for file in "${matched_files[@]}"; do
                        rm -f "$file" 2>/dev/null || true
                    done
                    log "→ Compressed ${#matched_files[@]} run_alerts logs for $date → $archive_name" "$LOG_FILE"
                else
                    log "❌ Failed to compress run_alerts logs for $date" "$LOG_FILE"
                fi
            fi
        done
    else
        log "→ No run_alerts logs to compress." "$LOG_FILE"
    fi
        
    # [2] 오래된 파일 삭제
    find "$LOG_ARCHIVE_DIR" -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_BASE" -type f -name "*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_ALERTS_DIR" -type f -name "run_alerts_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_BASE" -type f -name "alert_history.log" -mtime +90 -exec truncate -s 0 {} \;


    # [3] 로그 디렉토리 용량 체크
    if [ -d "$LOG_BASE" ]; then
        local total_size_kb
        total_size_kb=$(du -sk "$LOG_BASE" 2>/dev/null | awk '{print $1}' || echo 0)
        
        if [[ "$total_size_kb" =~ ^[0-9]+$ ]] && [ "$total_size_kb" -gt "$SIZE_THRESHOLD_KB" ]; then
            send_alert "Log Directory Size" "Log directory exceeds ${SIZE_THRESHOLD_KB} KB (actual: ${total_size_kb} KB)" "WARN" "clean_old_logs ($LOG_FILE)"
        fi
    fi
    
    # [4] 캐시 초기화
    rm -f "$LOG_BASE/.alert_sent_cache" 2>/dev/null || true
    
    log "→ clean_old_logs completed" "$LOG_FILE"
    return 0
}


# generate_summary(): 서버 상태 요약 보고서를 생성하고, CRIT/WARN 알림이 있는 경우 이메일로 전체 전송하고 슬랙에는 요약만 전송합니다.
# - 매 실행 시 'summary_current_<date>.log'로 저장되고, 직전 요약은 'summary_prev_<date>.log'로 백업됩니다.
# - 전체 내용은 GLOBAL_LOG에 남기지 않고, 결과 완료 메시지만 남깁니다.
generate_summary() {
    local SUMMARY_FILE="$LOG_BASE/summary_current_$(date +%F).log"
    local PREV_SUMMARY_FILE="$LOG_BASE/summary_prev_$(date +%F).log"

    # 기존 요약 로그가 있으면 백업
    if [ -f "$SUMMARY_FILE" ]; then
        mv "$SUMMARY_FILE" "$PREV_SUMMARY_FILE"
    fi

    log "====== generate_summary ======" "$SUMMARY_FILE"

    # 슬랙 요약 저장 변수 (slack은 한 길이 메시지당 제한 있어서 요약)
    local SLACK_MSG=""
    SLACK_MSG+="*Server Summary - $(hostname)* ($(date +%F))\n"
    log "--- Disk Usage Summary ---" "$SUMMARY_FILE"
    local disk_summary
    disk_summary=$(df -h | grep -vE "tmpfs|udev|loop")
    echo "$disk_summary" >> "$SUMMARY_FILE"

    local high_disks=$(echo "$disk_summary" | awk '$5+0 > 80 {print $0}')
    if [ -n "$high_disks" ]; then
        SLACK_MSG+="\n*Disk Usage* (over 80%):\n"
        SLACK_MSG+="\`\`\`$(echo "$high_disks" | awk '{print $6 ": " $5}' | head -5)\`\`\`"
    fi
    
    log "--- Disk Usage Change ---" "$SUMMARY_FILE"
    if [ -f "$LOG_BASE/.prev_disk_usage" ]; then
        local prev_disk_usage=$(cat "$LOG_BASE/.prev_disk_usage")
        echo "$prev_disk_usage" >> "$SUMMARY_FILE"
    else
        echo "(No previous usage data)" >> "$SUMMARY_FILE"
    fi

    log "--- LVM/Overlay/tmpfs Filesystems ---" "$SUMMARY_FILE"
    local lvm_info=$(df -hT | grep -E "lvm2|overlay|tmpfs")
    echo "$lvm_info" >> "$SUMMARY_FILE"


    log "--- Memory Usage Summary ---" "$SUMMARY_FILE"
    local mem_usage=$(free -h)
    echo "$mem_usage" >> "$SUMMARY_FILE"

    local mem_line=$(echo "$mem_usage" | grep -i "^Mem:")
    SLACK_MSG+="\n*Memory*: $mem_line"


    log "--- CPU Usage Summary ---" "$SUMMARY_FILE"
    local cpu_info=$(top -b -n 1 | head -15)
    echo "$cpu_info" >> "$SUMMARY_FILE"

    log "--- Load Average ---" "$SUMMARY_FILE"
    local uptime_info=$(uptime)
    echo "$uptime_info" >> "$SUMMARY_FILE"

    local load_avg=$(echo "$uptime_info" | sed 's/.*load average: //')
    SLACK_MSG+="\n*Load Average*: $load_avg"


    log "--- Reboot History ---" "$SUMMARY_FILE"
    local reboot_info
    reboot_info=$(uptime -s && last reboot | head -5)
    echo "$reboot_info" >> "$SUMMARY_FILE"

    log "--- Kernel Logs (dmesg tail) ---" "$SUMMARY_FILE"
    local dmesg_tail=$(dmesg -T | tail -10)
    echo "$dmesg_tail" >> "$SUMMARY_FILE"

    log "--- Services Status Summary ---" "$SUMMARY_FILE"
    SLACK_MSG+="\n*Services*:\n"
    for svc in "${SERVICES[@]}"; do
        local svc_status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        echo "$svc: $svc_status" >> "$SUMMARY_FILE"
        SLACK_MSG+="$svc: $svc_status  "
    done

    log "--- Recent Alerts Summary ---" "$SUMMARY_FILE"
    if [ -f "$RUN_ALERTS_FILE" ]; then
        local alerts=$(tail -n 20 "$RUN_ALERTS_FILE")
        echo "$alerts" >> "$SUMMARY_FILE"

        local alerts_summary=$(echo "$alerts" | grep -E "\[CRIT\]|\[WARN\]" | tail -5)
        if [ -n "$alerts_summary" ]; then
            SLACK_MSG+="\n\n*🚨 Recent Alerts*:\n\`\`\`$alerts_summary\`\`\`"
        fi
    fi

    # summary_only 모드 여부 감지
    IS_SUMMARY_ONLY=false
    if [[ "$1" == "summary_only" ]]; then
        IS_SUMMARY_ONLY=true
    fi
    
    # 알림 전송 조건: summary_only이거나 또는 최근에 WARN/CRIT 알림이 있었을 경우
    if $IS_SUMMARY_ONLY || grep -q "\[CRIT\]\|\[WARN\]" "$RUN_ALERTS_FILE"; then
        # 메일 전체 전송
        # mail -s "[$HOST_ID] Server Monitoring Summary - $(hostname) - $(date +%F)" "$ALERT_EMAIL" < "$SUMMARY_FILE"
        for email in $(echo "$ALERT_EMAIL" | tr ',' ' '); do
            {
                echo "From: $MAIL_FROM"
                echo "To: $email"
                echo "Subject: [$HOST_ID] Server Monitoring Summary - $(hostname) - $(date +%F)"
                echo
                cat "$SUMMARY_FILE"
            } | /usr/sbin/ssmtp -v "$email"
        done

        # 슬랙에는 상단 요약만 전송
        local slack_head=$(head -n 40 "$SUMMARY_FILE")
        local slack_payload=$(echo -e "$SLACK_MSG" | sed ':a;N;$!ba;s/\n/\\n/g' | cut -c1-3500)
        send_slack_alert "[$HOST_ID] Server Monitoring Summary - $(hostname) - $(date +%F)" "$slack_payload" "INFO"
    fi
}


### [19] 전체 모니터링 실행 #########################################
run_monitoring() {
    local MONITOR_LOG="$LOG_BASE/monitor_$(date +%F).log"
    log "=======================================================================" "$MONITOR_LOG"
    log "=== Server Monitoring Starting ($(date)) ===" "$MONITOR_LOG"

    ### 백업 시작 전에 bash_history 백업
    safe_run backup_bash_history

    ### [의존성 체크] RedHat 전용 처리 포함
    safe_run check_dependencies
    ### [시스템 및 리소스 요약]
    safe_run collect_system_summary
    safe_run check_reboot_event
    safe_run check_disk_usage
    # safe_run check_io_heavy_processes
    safe_run enhanced_io_monitoring
    safe_run check_network_status
    safe_run check_docker_volume_usage
    safe_run check_process_usage

    ### [서비스 상태 및 보안 모니터링]
    safe_run check_services
    safe_run check_system_temperature
    safe_run analyze_system_logs
    safe_run manage_zombie_processes
    safe_run analyze_container_logs

    ### [SSH 및 보안 설정 점검]
    safe_run monitor_ssh_stability    # SSH 연결 안정성 모니터링
    safe_run monitor_ssh_security     # SSH 보안 모니터링 (기존 check_fail2ban_status 및 로그인 실패 분석 통합)
    # SSH 자동 복구 기능은 ENABLE_SELF_HEALING이 true일 때만 실행
    if [ "$ENABLE_SELF_HEALING" = true ]; then
        safe_run optimize_sshd_config     # SSH 설정 최적화
        safe_run prioritize_sshd_service  # SSH 서비스 우선순위 조정
    fi

    # ==== [NEW] 커널/SSH/과부하 가드 ====
    safe_run ensure_kernel_watchdog_baseline
    safe_run check_softlockup_and_hung_tasks
    safe_run check_overload_and_stop_container
    safe_run check_and_recover_ssh_fallback
    # (선택) 권장 알림
    safe_run notify_rg_hardening_needed

    
    ### [자원 사용 자동 관리 및 정리]
    safe_run monitor_system_resources   
    # 조건부 실행 (리소스 자동 최적화는 여전히 위험하므로 제외하거나 매우 제한적으로만 포함)
    if [ "$ENABLE_SELF_HEALING" = true ]; then
        safe_run server_self_healing
    fi
    safe_run clean_old_logs
    
    ### [결과 요약 및 알림 발송]
    safe_run generate_summary

    log "=== Server Monitoring Completed ($(date)) ===" "$MONITOR_LOG"
    log "=======================================================================" "$MONITOR_LOG"
}

###################################

# 스크립트가 루트 권한으로 실행되는지 확인
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# summary_only 모드일 경우
if [ "${1:-}" = "summary_only" ]; then
    safe_run generate_summary
    exit 0
fi

# 전체 모니터링 실행
run_monitoring

exit 0

# 수동 실행 :   $ sudo bash ./server_monitoring.sh 
#              $ sudo bash ./server_monitoring.sh summary_only
# 프로세스 확인 : $ ps aux | grep server_monitoring.sh
# 스크립트 일부만 임시 실행 (인터랙티브 셸에서) : sudo bash -c 'source /home/user/arsim/opt_script/server_monitoring.sh && manage_zombie_processes'


### 크론탭 설정 가이드
# 1. 루트 크론탭 편집: sudo crontab -e
# 2. 다음 라인 추가:
#   */30 * * * * /home/user/arsim/opt_script/server_monitoring.sh >/dev/null 2>&1  # 30분마다 실행
#   */30 * * * * bash /home/user/arsim/opt_script/server_monitoring.sh >> /home/user/arsim/opt_script/log/cron_monitoring.log 2>&1

# 3. summary만 : 매일 오전 8시 summary 전송
#   0 8 * * * bash /home/user/arsim/opt_script/server_monitoring.sh summary_only >> /home/user/arsim/opt_script/log/daily_summary.log 2>&1


### 크론탭 테스트용 
# crontab 등록 (하루만)
#   $ (crontab -l; echo "*/30 * * * * /home/user/arsim/opt_script/server_monitoring.sh >/dev/null 2>&1") | crontab -
#   $ sudo sh -c '(crontab -l 2>/dev/null; echo "*/2 * * * * bash /home/user/arsim/opt_script/server_monitoring.sh >> /home/user/arsim/opt_script/log/cron_monitoring.log 2>&1") | crontab -'    

#   $ sudo sh -c '(crontab -l 2>/dev/null; echo "0 8 * * * bash /home/user/arsim/opt_script/server_monitoring.sh summary_only >> /home/user/arsim/opt_script/log/daily_summary.log 2>&1") | crontab -'    


# 하루 뒤 삭제 예약
#   $ echo "crontab -l | grep -v server_monitoring.sh | crontab -" | at now + 1 day
# 크롭탭 등록 확인
#   $ sudo crontab -l
# 크론탭 실제 작동 확인
#   $ grep CRON /var/log/syslog | grep server_monitoring.sh

### 추천 크론탭 설정:
#    */10 * * * *       # 10분마다 
#    0 */1 * * *        # 1시간마다
#    0 */6 * * * /      # 6시간마다 전체 모니터링
#    0 2 * * *           # 매일 새벽 2시 로그 정리

