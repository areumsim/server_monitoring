#!/bin/bash
# 디스크 모니터링 공통 설정 파일
#
# [사용법]
# 다른 모니터링 스크립트에서 source로 로드:
#   source /etc/ssmtp/disk_monitor_config.sh
#
# [설정 항목]
# - 모니터링 대상 파티션
# - 경고/위험 임계값 (%)
# - 알림 수신 이메일

# 모니터링 대상 파티션
PARTITION1="/data1"
PARTITION2="/data2"
PARTITION3="/dev/sda4"
PARTITION4="/var"

# 알림 임계값 (%)
THRESHOLD=70
WARNING_THRESHOLD=70
CRITICAL_THRESHOLD=80

# 알림 로그 파일 위치
ALERT_LOG="/etc/ssmtp/disk_alert_log.txt"

# 알림 간격 (시간)
ALERT_INTERVAL=1

# 알림 수신 이메일 주소 (쉼표로 구분)
EMAIL="admin@example.com"

# 발신 이메일 주소
MAIL_FROM="server@example.com"
