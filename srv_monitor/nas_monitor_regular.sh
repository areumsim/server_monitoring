#!/bin/bash
# NAS 디스크 사용량 모니터링 스크립트
#
# [개요]
# 원격 NAS 서버에 SSH 접속하여 디스크 사용량을 확인하고 이메일로 발송
#
# [사전 요구사항]
# - sshpass 설치: apt install sshpass
# - ssmtp 설정 완료 (이메일 발송용)
#
# [사용법]
# ./nas_monitor_regular.sh
#
# [cron 예시]
# 매일 오전 9시 실행: 0 9 * * * /path/to/nas_monitor_regular.sh

# 설정 파일 로드
CONFIG_FILE="/etc/ssmtp/disk_monitor_config.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "설정 파일을 찾을 수 없습니다: $CONFIG_FILE"
    exit 1
fi

EMAIL=${EMAIL:-"your-email@example.com"}

# NAS 서버 접속 정보
REMOTE_USER="root"              # SSH 접속 계정
REMOTE_HOST="###.###.###.###"   # NAS IP 주소
PASSWORD="########"             # SSH 비밀번호 (보안 주의: SSH 키 인증 권장)
PORT="9349"                     # SSH 포트 (기본: 22, 커스텀 포트 사용 시 변경)
CMD="df -h"                     # 실행할 명령어

output=$(sshpass -p "${PASSWORD}" ssh -o StrictHostKeyChecking=no -p "${PORT}" \
         "${REMOTE_USER}@${REMOTE_HOST}" "${CMD}")
subject="[NAS] 디스크 공간 정보"

echo "${output}"
echo -e "$output" | mail -s "$subject" $EMAIL
echo "경고 이메일을 보냈습니다."
