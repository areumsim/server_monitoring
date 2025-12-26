#!/bin/bash
# install_monitoring_suite.sh
# 운영 서버 자동화 설치 스크립트
#   - 모니터링 스크립트 배포
#   - crontab 등록
#   - logrotate 설정 포함

### 1. 변수 설정
SCRIPT_DIR="/opt/scripts"
MONITOR_SCRIPT_NAME="server_monitoring.sh"
CRON_SCHEDULE="*/60 * * * *"
LOGROTATE_CONF="/etc/logrotate.d/server_monitoring_logs"

### 2. 스크립트 디렉토리 생성 및 배포
mkdir -p "$SCRIPT_DIR"
echo "📁 복사 중: $MONITOR_SCRIPT_NAME → $SCRIPT_DIR"
cp "$MONITOR_SCRIPT_NAME" "$SCRIPT_DIR/"
chmod +x "$SCRIPT_DIR/$MONITOR_SCRIPT_NAME"

### 3. crontab 자동 등록
if ! crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT_NAME"; then
    echo "🕒 crontab 등록 중..."
    (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE bash $SCRIPT_DIR/$MONITOR_SCRIPT_NAME") | crontab -
else
    echo "✅ 이미 crontab에 등록됨"
fi

### 4. logrotate 설정 추가
if [ ! -f "$LOGROTATE_CONF" ]; then
    echo "📄 logrotate 설정 추가 중..."
    cat <<EOF > "$LOGROTATE_CONF"
/var/log/resource_monitor/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
else
    echo "✅ logrotate 설정 이미 존재함"
fi

### 완료 메시지
cat <<DONE
🎉 설치 완료!
- 모니터링 스크립트: $SCRIPT_DIR/$MONITOR_SCRIPT_NAME
- 로그 디렉토리: /var/log/resource_monitor
- crontab 주기: $CRON_SCHEDULE
- logrotate 설정 파일: $LOGROTATE_CONF
DONE



### 실행 
# $sudo bash install_monitoring_suite.sh
# 
### 동작
# 1. /opt/scripts/server_monitoring_suite.sh 위치로 복사
# 2. 실행 권한 부여 (chmod +x)
# 3. crontab에 자동 등록 → 매 5분마다 실행
# 4. /var/log/resource_monitor/*.log에 대해 logrotate 설정 추가
# 5. 필요한 경로/설정 출력
