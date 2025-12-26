#!/bin/bash
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
EMAIL=${EMAIL:-"ingwon_song@kolon.com,yeongsin_byeon@kolon.com,areum_sim@kolon.com,jungsoo_joo@kolon.com,na_li@kolon.com"}
MAIL_FROM=${MAIL_FROM:-"god6806@gmail.com"}
CRITICAL_THRESHOLD=${CRITICAL_THRESHOLD:-80}

# 디스크 사용량 확인 및 알림
check_and_alert() {
    local partition=$1
    local usage=$(LANG=C df -h | grep "$partition" | awk '{print $5}' | sed 's/%//' | head -n 1)
    
    if [[ "$usage" -ge "$CRITICAL_THRESHOLD" ]]; then
        local subject="[긴급] Server3 디스크 공간 부족 경고"
        local body="파티션 $partition의 사용량이 ${usage}%입니다.\n\n전체 디스크 상태:\n$(df -h)"
        
        # 이메일 전송
        echo -e "$body" | mail -s "$subject" $EMAIL
        
        # 로그 기록
        logger -t disk-quick-check "[경고] $partition: $usage% 사용중"
    fi
}

# 각 파티션 확인
check_and_alert "$PARTITION1"
check_and_alert "$PARTITION2"
check_and_alert "$PARTITION3"
check_and_alert "$PARTITION4"
