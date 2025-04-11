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

#######################################################################
### [1. 기본 경로 설정] ###############################################
#######################################################################
# 로그 디렉토리 설정
# LOG_BASE="/var/log/resource_monitor"
LOG_BASE="/home/user/arsim/opt_script/log"
LOG_ARCHIVE_DIR="${LOG_BASE}/archive"
LOG_ALERTS_DIR="${LOG_BASE}/run_alerts"

# 로그 파일 경로
GLOBAL_LOG="$LOG_BASE/global_$(date +%F).log"
RUN_ALERTS_FILE="${LOG_ALERTS_DIR}/run_alerts_$(date +%F_%H%M%S).log"

# 기타 경로 설정
LABEL_STUDIO_BACKUP_SCRIPT="/home/user/arsim/opt_script/label_studio_export_backup.py"

# 디렉토리 생성
mkdir -p "$LOG_BASE" "$LOG_ARCHIVE_DIR" "$LOG_ALERTS_DIR"
: > "$RUN_ALERTS_FILE"  # 알림 로그 파일 초기화

#######################################################################
### [2. 의존성 확인] ##################################################
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

#######################################################################
### [3. 모니터링 설정] ################################################
#######################################################################
# 임계값 설정
DISK_WARN=80           # 디스크 사용량 경고 임계치 (%)
DISK_CRIT=90           # 디스크 사용량 치명 임계치 (%)
DISK_INCREASE_THRESHOLD_GB=50  # 디스크 사용량 급격한 증가 감지를 위한 임계값 (GB 단위)

CPU_WARN_PERCENT=75    # CPU 사용량 경고 (%)
MEM_WARN_PERCENT=85    # 메모리 사용량 경고 (%)
PROCESS_MAX_HIT=3      # 동일 프로세스가 과다 자원 사용으로 감지되는 횟수

IO_WARN_THRESHOLD=30   # I/O 읽기+쓰기가 30% 이상인 프로세스 경고
IO_CRIT_THRESHOLD=50   # I/O 읽기+쓰기가 50% 이상인 프로세스 위험 알림

ZOMBIE_WARN_THRESHOLD=30    # 좀비 프로세스 경고 임계치
ZOMBIE_KILL_THRESHOLD=50    # 좀비 프로세스 강제 종료 임계치

TEMP_THRESHOLD=80      # 온도 경고 임계치 (°C)

# 로그 관리 설정
RETENTION_DAYS=30      # 로그 보관 기간 (일)
COMPRESS_DELAY=7       # N일 이상 지난 로그 파일을 압축
SIZE_THRESHOLD_KB=5242880  # 로그 디렉토리 용량 경고 임계치 (5GB in KB)

# 모니터링 대상 설정
SERVICES=("sshd" "docker" "nginx" "fail2ban")
PING_TARGETS=("8.8.8.8" "1.1.1.1")
MONITOR_INTERVAL=300   # 모니터링 실행 주기 (초) → crontab과는 별개

#######################################################################
### [4. 알림 설정] ####################################################
#######################################################################
# 알림 활성화 설정
ENABLE_EMAIL_ALERTS=true
ENABLE_SLACK_ALERTS=true
SEND_WARN_EMAILS=true     # WARN 레벨도 이메일로 받기

# 알림 대상 설정 
ALERT_EMAIL="areum_sim@kolon.com,yeongsin_byeon@kolon.com"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/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"

# 서버 자가 복구 기능 활성화 여부 (위험할 수 있으므로 기본은 false)
ENABLE_SELF_HEALING=false

### [공통 함수] ####################################################
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
    resolved_cmd=$(command -v "$cmd_name" 2>/dev/null || true)
    if [[ -z "$resolved_cmd" && -x "/sbin/$cmd_name" ]]; then
        resolved_cmd="/sbin/$cmd_name"
    elif [[ -z "$resolved_cmd" && -x "/usr/sbin/$cmd_name" ]]; then
        resolved_cmd="/usr/sbin/$cmd_name"
    fi

    if [[ -z "$resolved_cmd" ]]; then
        log "❌ Command not found: $cmd_name" "$LOG_FILE"
        send_alert "Command Not Found" "Command: $cmd_name" "ERROR" "run_cmd"
        return 127
    fi

    local timeout_secs=30
    local output
    output=$(timeout "$timeout_secs" "$resolved_cmd" "$@" 2>&1)
    local exit_code=$?

    echo "$output" >> "$LOG_FILE"

    local cmd_str="$resolved_cmd $(printf '%q ' "$@")"
    if [ $exit_code -ne 0 ]; then
        log "❌ Command failed: $cmd_str (exit $exit_code)" "$LOG_FILE"
        send_alert "Command Failed" "Command: $cmd_str\nExit code: $exit_code\nOutput:\n$output" "WARN" "run_cmd"
    else
        log "✅ Command success: $cmd_str" "$LOG_FILE"
    fi
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
        decorated_subject="-------- !!! [CRIT] Server Alert: $subject !!! --------"
    elif [ "$level" == "WARN" ]; then
        decorated_subject="-------- !! [WARN] Server Alert: $subject !! --------"
    else
        decorated_subject="[${level}] Server Alert: $subject"
    fi
    
    # 이메일 전송: CRIT는 무조건, WARN은 SEND_WARN_EMAILS가 true일 경우만 전송
    if { [ "$level" = "CRIT" ] || { [ "$level" = "WARN" ] && [ "$SEND_WARN_EMAILS" = true ]; }; } && [ "$ENABLE_EMAIL_ALERTS" = true ]; then
        # 이메일 전송 (쉼표 구분된 여러 메일 주소 지원)
        IFS=',' read -ra RECIPIENTS <<< "$ALERT_EMAIL"
        for email in "${RECIPIENTS[@]}"; do
            echo -e "$message" | mail -s "$decorated_subject" "$email"
        done
    fi

    # Slack 알림 전송: ENABLE_SLACK_ALERTS가 true일 경우
    if [ "$ENABLE_SLACK_ALERTS" = true ]; then
        send_slack_alert "$decorated_subject" "$message" "$level"
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
    run_cmd "$LOG_FILE" df -h >> "$LOG_FILE" || true
    
    # 네트워크 정보
    log "--- Network Info ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ip -s addr >> "$LOG_FILE" || true
    
    # 로그인된 사용자
    log "--- Logged in Users ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" w >> "$LOG_FILE" || true
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
        local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em|bond|wlan)')
        run_cmd "$LOG_FILE" ifstat -i $(echo "$interfaces" | tr '\n' ',') -b 1 1
    fi

    # 핑 테스트
    log "--- Ping Tests ---" "$LOG_FILE"
    local ping_failures=0
    for target in "${PING_TARGETS[@]}"; do
        log "Pinging $target..." "$LOG_FILE"
        if ! run_cmd "$LOG_FILE" timeout 5s ping -c 3 -W 2 "$target" >> "$LOG_FILE" 2>&1; then
            ping_failures=$((ping_failures + 1))
            log "⚠️ Failed to ping $target" "$LOG_FILE"
        fi
    done
    
    if [ $ping_failures -gt 0 ]; then
        send_alert "Network Connectivity Issues" "Failed to ping $ping_failures out of ${#PING_TARGETS[@]} targets." "WARN" "check_network_status ($LOG_FILE)"
    fi

    # DNS 해상도 테스트
    log "--- DNS Resolution Test ---" "$LOG_FILE"
    if ! run_cmd "$LOG_FILE" timeout 5s host -t A google.com >> "$LOG_FILE" 2>&1; then
        send_alert "DNS Resolution Failure" "Failed to resolve domain names. Check DNS configuration." "WARN" "check_network_status ($LOG_FILE)"
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

    local TMP_FILE=$(mktemp /tmp/high_usage_pids.XXXXXX) # mktemp를 사용하여 고유 임시 파일 생성
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
        tmp_pidstat_log=$(mktemp /tmp/pidstat_output.XXXXXX)

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
    
    log "→ check_io_heavy_processes completed" "$LOG_FILE"
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
           
    # 시스템 로그 분석
    run_cmd "$LOG_FILE" journalctl -p 0..3 -n 1000 --since "1 hour ago" | grep -Ei "$KEYWORDS" >> "$LOG_FILE" || true
    
    # 인증 로그 분석 (로그인 실패 및 보안 이벤트)
    log "--- Auth Log Analysis ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" grep -i "fail\|invalid\|error\|denied" /var/log/auth.log 2>/dev/null | tail -50 >> "$LOG_FILE" || true
    local ssh_failures
    
    # SSH 로그인 실패 건수를 최근 3시간 내에 발생한 건수로 필터링
    ssh_failures=0
    ssh_failures=$(journalctl -u sshd --since "3 hour ago" | grep -c "Failed password") || true
    if [ "$ssh_failures" -gt 10 ]; then
        send_alert "SSH Brute Force" "Detected $ssh_failures failed SSH login attempts in the past hour. Check for possible brute-force attacks." "WARN" "analyze_system_logs ($LOG_FILE)"
    fi

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

    local LOG_FILE="$LOG_BASE/zombie_proc_$(date +%F).log"
    log "====== manage_zombie_processes ======" "$LOG_FILE"



    # 좀비 프로세스 수 확인
    local zombie_count=0
    zombie_count=$(ps -eo stat | grep -c '^Z') || true
    log "→ Found $zombie_count zombie processes" "$LOG_FILE"

    declare -A container_zombie_count
    declare -A container_ppids

    if [ "$zombie_count" -ge "$ZOMBIE_WARN_THRESHOLD" ]; then
        local zombie_summary=""
        ps -eo pid,ppid,stat,cmd | awk '$3 ~ /Z/' | while read pid ppid stat cmd; do
            local cname
            cname=$(get_docker_container_name_by_pid "$ppid")
            if [ -n "$cname" ]; then
                if [ -z "${container_zombie_count[$cname]}" ]; then
                    container_zombie_count["$cname"]=1
                else
                    container_zombie_count["$cname"]=$((container_zombie_count["$cname"] + 1))
                fi

                container_ppids["$cname"]+="$ppid "
                log "→ Zombie PID $pid (parent: $ppid, container: $cname)" "$LOG_FILE"
                zombie_summary+="Zombie PID $pid (parent: $ppid, container: $cname)\n"
            else
                log "→ Zombie PID $pid (parent: $ppid, no container)" "$LOG_FILE"
                zombie_summary+="Zombie PID $pid (parent: $ppid, no container)\n"
            fi
        done

        send_alert "Zombie Processes" "High number of zombie processes: $zombie_count\n$zombie_summary" "WARN" "manage_zombie_processes ($LOG_FILE)"
    fi

    if [ "$zombie_count" -ge "$ZOMBIE_KILL_THRESHOLD" ]; then
        log "→ Zombie count exceeds kill threshold ($ZOMBIE_KILL_THRESHOLD), initiating cleanup" "$LOG_FILE"
        
        # SIGCHLD로 정리 시도
        for ppid in $(ps -eo ppid,stat | awk '$2=="Z" {print $1}' | sort | uniq); do
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

### [11] 백업 상태 확인 #############################################
# Label Studio 백업 스크립트를 실행하여 백업 성공 여부를 확인합니다.
# 백업 실패 시 치명 알림(CRIT)을 발송합니다.
check_labelStudio_backup_status() {
    local LOG_FILE="$LOG_BASE/backup_status_$(date +%F).log"
    log "====== check_labelStudio_backup_status ======" "$LOG_FILE"

    # Label Studio 백업 스크립트 실행
    if [ -f "$LABEL_STUDIO_BACKUP_SCRIPT" ]; then
        log "--- Label Studio Backup ---" "$LOG_FILE"
        if run_cmd "$LOG_FILE" timeout 60s python3 "$LABEL_STUDIO_BACKUP_SCRIPT" >> "$LOG_FILE" 2>&1; then
            log "✅ Label Studio backup SUCCESS" "$LOG_FILE"
        else
            log "❌ Label Studio backup FAILED" "$LOG_FILE"
            send_alert "Backup Failed" "Label Studio backup job failed. Please check the backup script and logs." "CRIT" "check_labelStudio_backup_status ($LOG_FILE)"
        fi
    else
        log "❌ Label Studio backup script not found at $LABEL_STUDIO_BACKUP_SCRIPT" "$LOG_FILE"
        send_alert "Backup Script Missing" "Label Studio backup script not found at expected location: $LABEL_STUDIO_BACKUP_SCRIPT" "WARN" "check_labelStudio_backup_status ($LOG_FILE)"
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
    
    if command -v docker &>/dev/null; then
        # 실행 중인 컨테이너 목록
        docker ps --format "{{.Names}}" | while read container; do
            log "-- 컨테이너 로그 분석: $container ------" "$LOG_FILE"
            
            # 오류 및 경고 로그 추출 (타임아웃 강제 종료 포함 + 실패 허용)
            if ! timeout --signal=SIGKILL 30s docker logs --tail 100 "$container" 2>&1 | \
               grep -iE "error|warn|exception|fail|fatal" | tail -10 >> "$LOG_FILE"; then
                log "⚠️ Timeout or error getting logs for $container (tail 100)" "$LOG_FILE"
            fi

            # 오류 빈도 확인 (tail 1000)
            local error_count
            error_count=$(timeout --signal=SIGKILL 10s docker logs --tail 1000 "$container" 2>&1 | \
                grep -icE "error|exception|fatal" 2>/dev/null || echo 0)

            if [[ "$error_count" =~ ^[0-9]+$ ]] && [ "$error_count" -gt 50 ]; then
                send_alert "Container Errors" \
                    "Container $container has $error_count errors in recent logs" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi
            
            # 재시작 수 확인
            local restart_count
            restart_count=$(docker inspect "$container" --format '{{.RestartCount}}' 2>/dev/null || echo 0)

            if [ "$restart_count" -gt 5 ]; then
                send_alert "Container Restarts" \
                    "Container $container has restarted $restart_count times" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi
        done
    else
        log "❌ Docker command not found. Container log analysis skipped." "$LOG_FILE"
    fi
}


### [16] SSH 세션 이상 감지 #########################################
# SSH 연결 안정성 모니터링 (연결 끊김, 세션, 설정 문제 등에 집중)
monitor_ssh_stability() {
    local LOG_FILE="$LOG_BASE/ssh_stability_$(date +%F).log"
    log "====== monitor_ssh_stability ======" "$LOG_FILE"

    ## [1] SSH 연결 끊김 횟수 (최근 1시간)
    local disconnects=0
    if command -v journalctl &>/dev/null; then
        disconnects=$(run_cmd "$LOG_FILE" timeout 5s journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -Ei "Connection closed|Disconnecting" | wc -l | tr -d ' \n\t\r' || echo 0)
    else
        disconnects=$(grep -Ei "Connection closed|Disconnecting" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %e')" | wc -l | tr -d ' \n\t\r' || echo 0)
    fi

    if ! [[ "$disconnects" =~ ^[0-9]+$ ]]; then
        disconnects=0
    fi
    log "→ SSH disconnections (last 1h): $disconnects" "$LOG_FILE"

    # 너무 자주 끊긴다면 경고
    if [ "$disconnects" -ge 10 ]; then
        send_alert "Frequent SSH Disconnects" "Detected $disconnects SSH disconnections in the past hour. Check for instability or fail2ban misfire." "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [2] 현재 로그인 세션 수
    local active_sessions=0
    active_sessions=$(who 2>/dev/null | wc -l | tr -d ' \n\t\r' || echo 0)
    if ! [[ "$active_sessions" =~ ^[0-9]+$ ]]; then
        active_sessions=0
    fi
    
    log "→ Current active SSH sessions: $active_sessions" "$LOG_FILE"

    if [ "$active_sessions" -gt 50 ]; then
        send_alert "Too Many Active Sessions" "There are $active_sessions active user sessions. Potential misuse or DoS attempt." "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [3] CLOSE_WAIT 세션 수 (소켓 누수 가능성)
    local close_wait_count=0
    close_wait_count=$(run_cmd "$LOG_FILE" timeout 5s ss -tan 2>/dev/null | grep CLOSE-WAIT | wc -l | tr -d ' \n\t\r' || echo 0)
    
    if ! [[ "$close_wait_count" =~ ^[0-9]+$ ]]; then
        close_wait_count=0
    fi
    log "→ Current CLOSE_WAIT sockets: $close_wait_count" "$LOG_FILE"

    if [ "$close_wait_count" -gt 100 ]; then
        send_alert "Excessive CLOSE_WAIT" "Detected $close_wait_count CLOSE_WAIT sockets. Possible socket leak or stuck sessions." "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [4] SSH 설정 안정성 검사
    local ClientAliveInterval=0
    local ClientAliveCountMax=3
    local ssh_config="/etc/ssh/sshd_config"
    
    if [ -f "$ssh_config" ]; then
        ClientAliveInterval=$(grep -E "^[[:space:]]*ClientAliveInterval" "$ssh_config" 2>/dev/null | awk '{print $2}' || echo "0")
        ClientAliveCountMax=$(grep -E "^[[:space:]]*ClientAliveCountMax" "$ssh_config" 2>/dev/null | awk '{print $2}' || echo "3")
    elif [ -d "/etc/ssh/sshd_config.d" ]; then
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf_file" ]; then
                if grep -q "ClientAliveInterval" "$conf_file"; then
                    ClientAliveInterval=$(grep -E "^[[:space:]]*ClientAliveInterval" "$conf_file" | awk '{print $2}')
                fi
                if grep -q "ClientAliveCountMax" "$conf_file"; then
                    ClientAliveCountMax=$(grep -E "^[[:space:]]*ClientAliveCountMax" "$conf_file" | awk '{print $2}')
                fi
            fi
        done
    fi
    
    log "→ SSH keepalive settings: ClientAliveInterval=$ClientAliveInterval, ClientAliveCountMax=$ClientAliveCountMax" "$LOG_FILE"
    
    if [ "$ClientAliveInterval" = "0" ] || [ "$ClientAliveInterval" -gt 60 ]; then
        send_alert "SSH Config Issue" "SSH ClientAliveInterval is $ClientAliveInterval. Recommended: 30 (to detect stale sessions early)." "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi
}

# SSH 보안 모니터링 (로그인 실패, 차단된 IP, 브루트포스 공격 등에 집중)
monitor_ssh_security() {
    local LOG_FILE="$LOG_BASE/ssh_security_$(date +%F).log"
    log "====== monitor_ssh_security ======" "$LOG_FILE"

    ## [1] SSH 로그인 실패 시도 감지 (로그 파일 분석)
    local failed_logins=0
    failed_logins=$(run_cmd "$LOG_FILE" grep -i "Failed password" /var/log/auth.log 2>/dev/null | wc -l | tr -d ' \n\t\r' || echo 0)
    [[ "$failed_logins" =~ ^[0-9]+$ ]] || failed_logins=0
    
    log "→ SSH failed login attempts (total): $failed_logins" "$LOG_FILE"
    
    # 최근 실패 (journalctl이 있는 경우 더 정확한 시간 필터링 가능)
    local recent_failures=0
    if command -v journalctl &>/dev/null; then
        recent_failures=$(run_cmd "$LOG_FILE" timeout 5s journalctl -u sshd --since "3 hour ago" 2>/dev/null | grep -c "Failed password" || echo 0)
        [[ "$recent_failures" =~ ^[0-9]+$ ]] || recent_failures=0
        log "→ Recent SSH login failures (3h): $recent_failures" "$LOG_FILE"
    fi
    
    # 경고 생성 (최근 실패가 확인된 경우 그 값 사용, 아니면 전체 실패 수 기준)
    local threshold_count=${recent_failures:-$failed_logins}
    local threshold=20
    
    # 값이 숫자인지 확인하고 임계값과 비교
    if [[ "$threshold_count" =~ ^[0-9]+$ ]] && [ "$threshold_count" -ge "$threshold" ]; then
        # 공격자 IP 통계 (상위 5개만)
        local attacking_ips
        attacking_ips=$(run_cmd "$LOG_FILE" grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort | uniq -c | sort -nr | head -5 || echo "IP 정보를 추출할 수 없습니다.")
        send_alert "SSH Brute Force Attempt" \
            "Detected $threshold_count failed SSH login attempts.\nTop attacking IPs:\n$attacking_ips" \
            "WARN" "monitor_ssh_security ($LOG_FILE)"
    fi

    ## [2] fail2ban 상태 확인 (설치된 경우)
    if command -v fail2ban-client &> /dev/null; then
        log "--- Fail2Ban Status ---" "$LOG_FILE"
        
        # fail2ban 서비스 상태 확인
        if ! systemctl is-active --quiet fail2ban; then
            send_alert "Fail2Ban Not Running" "fail2ban 서비스가 실행되지 않고 있습니다." "WARN" "monitor_ssh_security ($LOG_FILE)"
            log "→ fail2ban service is not running" "$LOG_FILE"
            return
        fi
        
        # sshd jail 상태 확인
        local status_output
        status_output=$(run_cmd "$LOG_FILE" timeout 5s fail2ban-client status sshd 2>&1 || echo "Failed to get fail2ban status")
        echo "$status_output" >> "$LOG_FILE"
        
        # 차단된 IP 추출
        local banned_ips
        banned_ips=$(echo "$status_output" | grep 'Banned IP list:' | cut -d: -f2- | tr -s ' ' | sed 's/^ //' || echo "")
        
        if [ -n "$banned_ips" ]; then
            local banned_count=$(echo "$banned_ips" | wc -w || echo 0)
            log "→ Currently banned IPs: $banned_count" "$LOG_FILE"
            
            # IP 목록 저장 및 새로운 IP 확인
            local banned_ips_file="/tmp/fail2ban_current_ips.txt"
            local banned_ips_old_file="/tmp/fail2ban_prev_ips.txt"
            
            echo "$banned_ips" | tr ' ' '\n' | sort > "$banned_ips_file" || true
            
            local new_ips=""
            if [ -f "$banned_ips_old_file" ]; then
                new_ips=$(comm -23 <(sort "$banned_ips_file") <(sort "$banned_ips_old_file") || echo "$banned_ips")
            else
                new_ips="$banned_ips"
            fi
            
            cp "$banned_ips_file" "$banned_ips_old_file" || true
            
            # 새로 차단된 IP가 있으면 알림 (공백/빈 줄만 있을 경우도 제외)
            if [ -n "$(echo "$new_ips" | tr -d '[:space:]')" ]; then
                local timestamp=$(date '+%F %T')
                echo "[$timestamp] Banned IPs: $banned_ips" >> "$LOG_BASE/fail2ban_ip_history.log" || true
                # 슬랙으로 보내기 전에 디버그용 로그도 남기기
                echo "Newly Banned IPs (for Slack): $new_ips" >> "$LOG_FILE"
                
                send_alert "Fail2Ban Banned IPs" "Newly banned IPs:\n$new_ips" "WARN" "monitor_ssh_security ($LOG_FILE)"
            else
                log "→ No newly banned IPs detected." "$LOG_FILE"
            fi
        fi  
        # 반복 차단 IP 분석 (fail2ban_ip_history.log가 있는 경우)
        if [ -f "$LOG_BASE/fail2ban_ip_history.log" ]; then
            log "--- Repeat Offender Analysis ---" "$LOG_FILE"
            run_cmd "$LOG_FILE" tail -n 1000 "$LOG_BASE/fail2ban_ip_history.log" | \
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 > /tmp/fail2ban_stats.txt || true

            cat /tmp/fail2ban_stats.txt >> "$LOG_FILE" || true

            while read -r count ip; do
                if [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -ge 5 ]; then
                    send_alert "Repeat Fail2Ban Offender" \
                        "IP $ip was banned $count times recently.\nConsider permanent blocking at firewall level." \
                        "WARN" "monitor_ssh_security ($LOG_FILE)"
                fi
            done < /tmp/fail2ban_stats.txt 2>/dev/null || true
        fi

    else
        log "→ fail2ban is not installed" "$LOG_FILE"
        send_alert "Fail2Ban Missing" "fail2ban이 설치되어 있지 않습니다. 서버 보안을 위해 설치를 권장합니다." "WARN" "monitor_ssh_security ($LOG_FILE)"
    fi
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

    log "System load: $load_avg (CPU count: $cpu_count, threshold: $load_threshold)" "$LOG_FILE"

    local is_overloaded=0
    if command -v bc &>/dev/null; then
        is_overloaded=$(echo "$load_avg > $load_threshold" | bc -l 2>/dev/null || echo "0")
    else
        local load_int=${load_avg%.*}
        [ "$load_int" -gt "$load_threshold" ] && is_overloaded=1 || is_overloaded=0
    fi

    if [ "$is_overloaded" -eq 1 ]; then
        send_alert "High System Load" "System load ($load_avg) exceeds threshold ($load_threshold)." "WARN" "manage_high_load ($LOG_FILE)"

        log "--- Top CPU Processes ---" "$LOG_FILE"
        ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu 2>/dev/null | head -10 >> "$LOG_FILE" || true
    fi
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



### [14] 로그 정리 및 요약 #########################################
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
    
    # [2] 오래된 파일 삭제
    find "$LOG_ARCHIVE_DIR" -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_BASE" -type f -name "*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_ALERTS_DIR" -type f -name "run_alerts_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    
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

    log "--- Disk Usage Summary ---" "$SUMMARY_FILE"
    local disk_output=$(df -h | grep -vE "tmpfs|udev|loop")
    echo "$disk_output" >> "$SUMMARY_FILE"

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
    local mem_info=$(free -h)
    echo "$mem_info" >> "$SUMMARY_FILE"

    log "--- CPU Usage Summary ---" "$SUMMARY_FILE"
    local cpu_info=$(top -b -n 1 | head -15)
    echo "$cpu_info" >> "$SUMMARY_FILE"

    log "--- Load Average ---" "$SUMMARY_FILE"
    local uptime_info=$(uptime)
    echo "$uptime_info" >> "$SUMMARY_FILE"

    log "--- Reboot History ---" "$SUMMARY_FILE"
    local reboot_info
    reboot_info=$(uptime -s && last reboot | head -5)
    echo "$reboot_info" >> "$SUMMARY_FILE"

    log "--- Kernel Logs (dmesg tail) ---" "$SUMMARY_FILE"
    local dmesg_tail=$(dmesg -T | tail -10)
    echo "$dmesg_tail" >> "$SUMMARY_FILE"

    log "--- Services Status Summary ---" "$SUMMARY_FILE"
    for svc in "${SERVICES[@]}"; do
        local status
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        echo "$svc: $status" >> "$SUMMARY_FILE"
    done

    log "--- Recent Alerts Summary ---" "$SUMMARY_FILE"
    if [ -f "$RUN_ALERTS_FILE" ]; then
        local alert_tail=$(tail -n 20 "$RUN_ALERTS_FILE")
        echo "$alert_tail" >> "$SUMMARY_FILE"
    fi

    # 알림 전송 조건: CRIT 또는 WARN이 최근에 있었던 경우
    if grep -q "\[CRIT\]\|\[WARN\]" "$RUN_ALERTS_FILE"; then
        # 메일 전체 전송
        mail -s "Server Monitoring Summary - $(hostname) - $(date +%F)" "$ALERT_EMAIL" < "$SUMMARY_FILE"

        # 슬랙에는 상단 요약만 전송
        local slack_head=$(head -n 40 "$SUMMARY_FILE")
        send_slack_alert "Server Monitoring Summary - $(hostname) - $(date +%F)" "$slack_head" "INFO"
    fi
}


### [15] 로그 정리 및 요약 #########################################
run_monitoring() {
    local MONITOR_LOG="$LOG_BASE/monitor_$(date +%F).log"
    log "=======================================================================" "$MONITOR_LOG"
    log "=== Server Monitoring Starting ($(date)) ===" "$MONITOR_LOG"
    
    ### [시스템 및 리소스 요약]
    safe_run collect_system_summary
    safe_run check_disk_usage
    safe_run check_io_heavy_processes
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

    
    ### [자원 사용 자동 관리 및 정리]
    safe_run monitor_system_resources   
    # 조건부 실행 (리소스 자동 최적화는 여전히 위험하므로 제외하거나 매우 제한적으로만 포함)
    if [ "$ENABLE_SELF_HEALING" = true ]; then
        safe_run server_self_healing 
    fi
    # check_labelStudio_backup_status    
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

# 전체 모니터링 실행
run_monitoring

exit 0

# 수동 실행 :  $ sudo bash ./server_monitoring.sh
# 프로세스 확인 : $ ps aux | grep server_monitoring.sh
# 스크립트 일부만 임시 실행 (인터랙티브 셸에서) : sudo bash -c 'source /home/user/arsim/opt_script/server_monitoring.sh && manage_zombie_processes'


### 크론탭 설정 가이드
# 1. 루트 크론탭 편집: sudo crontab -e
# 2. 다음 라인 추가:
#   */30 * * * * /home/user/arsim/opt_script/server_monitoring.sh >/dev/null 2>&1  # 30분마다 실행
#   */30 * * * * bash /home/user/arsim/opt_script/server_monitoring.sh >> /home/user/arsim/opt_script/log/cron_monitoring.log 2>&1

### 크론탭 테스트용 
# crontab 등록 (하루만)
#   $ (crontab -l; echo "*/30 * * * * /home/user/arsim/opt_script/server_monitoring.sh >/dev/null 2>&1") | crontab -
#   $ (crontab -l 2>/dev/null; echo "*/30 * * * * bash /home/user/arsim/opt_script/server_monitoring.sh >> /home/user/arsim/opt_script/log/cron_monitoring.log 2>&1") | crontab -
# 하루 뒤 삭제 예약
#   $ echo "crontab -l | grep -v server_monitoring.sh | crontab -" | at now + 1 day
# 크롭탭 등록 확인
#   $ crontab -l
# 크론탭 실제 작동 확인
#   $ grep CRON /var/log/syslog | grep server_monitoring.sh

### 추천 크론탭 설정:
#    */10 * * * *       # 10분마다 
#    0 */1 * * *        # 1시간마다
#    0 */6 * * * /      # 6시간마다 전체 모니터링
#    0 2 * * *           # 매일 새벽 2시 로그 정리

