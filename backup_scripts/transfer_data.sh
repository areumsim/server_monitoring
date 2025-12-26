#!/bin/bash
# transfer_data.sh

# 로그 파일 설정
LOG_BASE="/home/user/arsim/opt_script/log"
LOG_FILE="$LOG_BASE/transfer_log_$(date +%Y%m%d_%H%M%S).log"

# 대상 경로 설정
DEST="/data2/nas_kbn02_01/backup/sv3_bu_250326/"

# 전송 함수 (진행 상황 표시 및 로깅 포함)
transfer() {
    echo "$(date): $1 전송 시작" | tee -a $LOG_FILE
    rsync -av --partial --progress --stats "$1" "$DEST" 2>&1 | tee -a $LOG_FILE
    if [ $? -eq 0 ]; then
        echo "$(date): $1 전송 성공" | tee -a $LOG_FILE
    else
        echo "$(date): $1 전송 실패" | tee -a $LOG_FILE
    fi
    echo "----------------------------" | tee -a $LOG_FILE
}

# 우선순위 순서대로 전송
transfer "/data2/labelstudio"
transfer "/home/user/yplee"
transfer "/home/user/ysbyeon"
transfer "/home/user/arsim"
transfer "/data1/arsim"

echo "모든 전송 작업 완료" | tee -a $LOG_FILE
