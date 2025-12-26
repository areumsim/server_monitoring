#!/bin/bash

# 스크립트 에러 처리 강화
set -euo pipefail
trap 'echo "스크립트 실행 중 에러 발생"; exit 1' ERR

# 설정 파일 로드
CONFIG_FILE="/etc/ssmtp/disk_monitor_config.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "설정 파일을 찾을 수 없습니다: $CONFIG_FILE"
    exit 1
fi

# 기본 설정값 (설정 파일에서 정의되지 않은 경우 사용)
PARTITION1=${PARTITION1:-"/data1"}
PARTITION2=${PARTITION2:-"/data2"}
PARTITION3=${PARTITION3:-"/dev/sda4"}
PARTITION4=${PARTITION4:-"/var"}
THRESHOLD=${THRESHOLD:-80}
WARNING_THRESHOLD=${WARNING_THRESHOLD:-70}
CRITICAL_THRESHOLD=${CRITICAL_THRESHOLD:-90}
ALERT_LOG=${ALERT_LOG:-"/etc/ssmtp/disk_alert_log.txt"}
ALERT_INTERVAL=${ALERT_INTERVAL:-1}
EMAIL=${EMAIL:-"ingwon_song@kolon.com,yeongsin_byeon@kolon.com,areum_sim@kolon.com,jungsoo_joo@kolon.com,na_li@kolon.com"}
MAIL_FROM=${MAIL_FROM:-"god6806@gmail.com"}
USAGE_HISTORY_FILE="/etc/ssmtp/disk_usage_history.log"
MONITOR_LOG="/etc/ssmtp/disk_monitor.log"

# 로그 함수
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$MONITOR_LOG"
}

# 디스크 사용량 확인 함수
check_disk_usage() {
    local partition=$1
    local usage=$(LANG=C df -h | grep "$partition" | awk '{print $5}' | sed 's/%//' | head -n 1)
    if [[ ! "$usage" =~ ^[0-9]+$ ]]; then
        log_message "오류: $partition의 디스크 사용량을 가져올 수 없습니다."
        return 1
    fi
    echo "$usage"
}

# 대용량 파일 찾기
get_large_files() {
    local partition=$1
    log_message "가장 큰 파일/디렉토리 목록 ($partition):"
    du -h --max-depth=1 "$partition" 2>/dev/null | sort -rh | head -n 5 >> "$MONITOR_LOG"
    find "$partition" -maxdepth 3 -type f -mtime +30 -size +100M 2>/dev/null | head -n 100 >> "$MONITOR_LOG"
}

# 시스템 리소스 확인
check_system_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    local memory_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    log_message "CPU 사용률: $cpu_usage%"
    log_message "메모리 사용률: $memory_usage%"
}

# I/O 통계 수집
collect_io_stats() {
    log_message "디스크 I/O 통계:"
    iostat -x 1 5 | grep -v '^$' | grep -v 'avg-cpu' >> "$MONITOR_LOG"
}


# 사용량 히스토리 저장
save_usage_history() {
    local usage1=$1
    local usage2=$2
    local usage3=$3
    local usage4=$4
    echo "$(date +%s) $usage1 $usage2 $usage3 $usage4" >> "$USAGE_HISTORY_FILE"
}

# 증가율 계산
calculate_growth_rate() {
    local partition=$1
    local partition_id=$2
    log_message "partition_id: $partition_id"
    if [ -f "$USAGE_HISTORY_FILE" ]; then
        local week_ago_usage=$(tail -n 7 "$USAGE_HISTORY_FILE" | head -n 1 | awk -v partition_id="$partition_id" '{print $partition_id}')
        local current_usage=$(tail -n 1 "$USAGE_HISTORY_FILE" | awk -v partition_id="$partition_id" '{print $partition_id}')
        local week_ago_time=$(tail -n 7 "$USAGE_HISTORY_FILE" | head -n 1 | awk '{print $1}')
	local current_time=$(tail -n 1 "$USAGE_HISTORY_FILE" | awk '{print $1}')
	log_message "current_usage: $current_usage , current_time: $current_time"
	log_message "week_ago_usage: $week_ago_usage , week_ago_time: $week_ago_time"
	local growth_rate=$(( ($current_usage - $week_ago_usage) / 7 ))
        log_message "growth_rate: $growth_rate"
	echo "$growth_rate"
    else
        echo "0"
    fi
}

# 디스크 포화 예측
predict_disk_full() {
    local current_usage=$1
    local growth_rate=$2
    if [ "$growth_rate" -gt 0 ]; then
        local days_until_full=$(( (100 - current_usage) / growth_rate ))
        log_message "예상 포화 시간: $days_until_full 일"
    fi
}

# 알림 전송
send_alert() {
    local subject="$1"
    local body="$2"
    local severity="$3"
    echo $body
    echo $subject
    echo $severity

    # 이메일 전송
    echo -e "t" | mail -s "t" god6806@gmail.com
    echo -e "$body" | mail -s "$subject" $EMAIL
    # echo -e "From: $MAIL_FROM\nTo: $EMAIL\nSubject: $subject\n\n$body" | /usr/sbin/ssmtp -v $EMAIL

    log_message "경고 메시지 전송 완료 (심각도: $severity)"
}

check_container_cpu_usage() {
    log_message "도커 컨테이너 CPU 사용량 확인 중..."
    local container_cpu_stats
    # docker stats 명령어 실행 및 상위 10개 정렬
    # 오류 발생 시 빈 문자열 반환 또는 오류 메시지 로깅
    if command -v docker &> /dev/null; then
        container_cpu_stats=$(docker stats --no-stream --format "table {{.Container}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | sort -k3 -hr | head -n 10)
        if [ -n "$container_cpu_stats" ]; then
            log_message "도커 컨테이너 CPU 사용량 수집 완료."
            echo -e "\n도커 컨테이너 CPU 사용량 (상위 10개):\n$container_cpu_stats"
        else
            log_message "도커 컨테이너 CPU 사용량 정보를 가져올 수 없거나 실행 중인 컨테이너가 없습니다."
            echo -e "\n도커 컨테이너 CPU 사용량: 정보를 가져올 수 없거나 실행 중인 컨테이너가 없습니다."
        fi
    else
        log_message "Docker 명령어를 찾을 수 없습니다. 컨테이너 CPU 사용량을 확인할 수 없습니다."
        echo -e "\n도커 컨테이너 CPU 사용량: Docker가 설치되어 있지 않거나 실행 중이 아닙니다."
    fi
}

# 메인 로직
main() {
    log_message "디스크 모니터링 시작"

    # 현재 시간
    current_time=$(date +%s)
    # 디스크 사용량 확인
    usage1=$(check_disk_usage "$PARTITION1") #/data1 제일 높은 사용률 1개
    usage2=$(check_disk_usage "$PARTITION2") #/data2 
    usage3=$(check_disk_usage "$PARTITION3") #/dev/sda4
    usage4=$(check_disk_usage "$PARTITION4") #/var
    
    # 사용량 히스토리 저장
    save_usage_history "$usage1" "$usage2" "$usage3" "$usage4" #히스토리 파일 "/etc/ssmtp/disk_usage_history.log" 저장
    
    # 마지막 알림 시간 확인
    if [[ -f "$ALERT_LOG" ]]; then
        last_alert_time=$(cat "$ALERT_LOG")
        if [[ ! "$last_alert_time" =~ ^[0-9]+$ ]]; then
            log_message "오류: 알림 로그 파일의 형식이 잘못되었습니다."
            exit 1
        fi
    else
        last_alert_time=0
    fi
    
    # 알림 조건 확인
    alert_needed=false
    alert_body="디스크 사용량 보고:\n\n"
    severity="INFO"

    partitions=( "$PARTITION1" "$PARTITION2" "$PARTITION3" "$PARTITION4" )
    list="0 1 2 3"
    for var in ${list}; do
        local partition=${partitions[$var]}
	local usage=$(check_disk_usage "$partition")
	local growth_rate=$(calculate_growth_rate "$partition" "$((var+2))")
        
        alert_body+="$((var+1))번째 파티션\n"
        alert_body+="파티션 정보: $partition\n"
        alert_body+="사용률: ${usage}%\n"
        alert_body+="주간 증가율: ${growth_rate}%일\n\n"
        #alert_body+="파티션 $partition: ${usage}% 사용중\n"
        #alert_body+="주간 증가율: ${growth_rate}%/일\n\n"
        
        if [ "$usage" -gt "$CRITICAL_THRESHOLD" ]; then
	    alert_needed=true
            severity="CRITICAL"
            # get_large_files "$partition"
        elif [ "$usage" -gt "$WARNING_THRESHOLD" ]; then
            alert_needed=true
            [ "$severity" != "CRITICAL" ] && severity="WARNING"
        fi
        predict_disk_full "$usage" "$growth_rate"
    done

        # 미사용 도커 이미지 확인
    alert_body+="\n미사용 도커 이미지 목록:\n"
    while read -r image_id repository tag image_size; do
        container_count=$(docker ps -a --filter "ancestor=$image_id" --format "{{.ID}}" | wc -l)
        if [ "$container_count" -eq 0 ]; then
            alert_body+="[IMAGE ID]: $image_id  /  [REPOSITORY]: $repository  /  [TAG]: $tag  /  [SIZE]: $image_size\n"
        fi
    done < <(docker images --format "{{.ID}} {{.Repository}} {{.Tag}} {{.Size}}" | tail -n +2 | sort -hr -k3)

    # 컨테이너별 디스크 사용량 확인
    alert_body+="\n도커 컨테이너별 디스크 사용량:\n"
    while read -r container_id container_name container_size; do
        if [[ -z "$container_size" ]]; then
            container_size="N/A"
        fi
        alert_body+="[CONTAINER ID]: $container_id  /  [NAMES]: $container_name  /  [SIZE]: $container_size\n"
    done < <(docker ps -s --format "{{.ID}} {{.Names}} {{.Size}}" | sort -hr -k3)
    
    container_cpu_info=$(check_container_cpu_usage)
    alert_body+="$container_cpu_info\n"

    # 시스템 리소스 확인
    check_system_resources
    collect_io_stats
    
    # 전체 디스크 상태 추가
    alert_body+="\n전체 디스크 상태:\n$(df -h)\n"
    
    log_message "alert_needed: $alert_needed"
    # 알림 전송 조건 확인
    if [ "$alert_needed" = true ] || [ $(($current_time - $last_alert_time)) -ge "$ALERT_INTERVAL" ]; then
        send_alert "[Server3] 디스크 공간 상세 정보" "$alert_body" "$severity"
        echo "$current_time" > "$ALERT_LOG"
    else
        log_message "현재 디스크 사용량은 정상 범위 내에 있거나 알림 간격이 지나지 않았습니다."
    fi
    
    log_message "디스크 모니터링 완료"
}

# 스크립트 실행
main
