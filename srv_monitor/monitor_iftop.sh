#!/bin/bash
# 설정
INTERFACE="ens6f0"
THRESHOLD=1  # 1Mbps 임계값 (Mbps 단위)
LOG_BASE_DIR="/var/log/vpn_traffic"
INTERVAL=5  # 10초 간격

# 로그 디렉토리 생성 함수
create_log_path() {
    local current_date=$(date '+%Y-%m-%d')
    local current_hour=$(date '+%H')
    local date_dir="$LOG_BASE_DIR/$current_date"
    
    # 날짜 디렉토리 생성
    sudo mkdir -p "$date_dir"
    sudo chmod 755 "$date_dir"
    
    # 로그 파일 경로 설정
    echo "$date_dir/${current_date}.${current_hour}.log"
}

# 초기 로그 디렉토리 생성
sudo mkdir -p $LOG_BASE_DIR
sudo chmod 755 $LOG_BASE_DIR

# 단위를 Mbps로 변환하는 함수
convert_to_mbps() {
    local value=$1
    local number=$(echo "$value" | grep -o '[0-9.]*')
    local unit=$(echo "$value" | grep -o '[KMGTkmgt][bB]*')
    
    case $unit in
        "Kb"|"kb"|"KB") echo "scale=3; $number / 1000" | bc -l ;;
        "Mb"|"mb"|"MB") echo "$number" ;;
        "Gb"|"gb"|"GB") echo "scale=2; $number * 1000" | bc -l ;;
        "Tb"|"tb"|"TB") echo "scale=2; $number * 1000000" | bc -l ;;
        "b"|"B"|"") echo "scale=6; $number / 1000000" | bc -l ;;  # bytes를 Mbps로
        *) echo "scale=3; $number / 1000" | bc -l ;;  # 기본값은 Kb로 가정
    esac
}

# 무한 루프
while true; do
    # 현재 타임스탬프
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 현재 시간에 맞는 로그 파일 경로 생성
    LOGFILE=$(create_log_path)
    
    # 로그 파일 권한 설정 (새 파일인 경우)
    if [[ ! -f "$LOGFILE" ]]; then
        sudo touch "$LOGFILE"
        sudo chmod 644 "$LOGFILE"
    fi
    
    # iftop 실행 후 출력 캡처
    OUTPUT=$(sudo iftop -i $INTERFACE -t -P -s $INTERVAL 2>&1)
    
    # 임시 파일에 출력 저장
    echo "$OUTPUT" > /tmp/iftop_output.txt
    
    # 연결 라인 추출 (=> 가 있는 라인과 그 다음 <= 라인을 쌍으로 처리)
    grep -n "=>" /tmp/iftop_output.txt | while read -r line; do
        line_num=$(echo "$line" | cut -d: -f1)
        send_line=$(echo "$line" | cut -d: -f2-)
        
        # 다음 라인 (receive 라인) 가져오기
        next_line_num=$((line_num + 1))
        recv_line=$(sed -n "${next_line_num}p" /tmp/iftop_output.txt)
        
        # send 라인 파싱: server3:3000 => 192.168.89.113:12353 145Kb 165Kb 165Kb 206KB
        if [[ "$send_line" =~ "=>" ]] && [[ "$send_line" =~ [0-9]+[KMGTkmgtbB] ]]; then
            
            # 송신 정보 추출 (=> 기준으로 분리)
            source=$(echo "$send_line" | sed 's/^[ ]*[0-9]* *//' | awk '{print $1}')
            dest_and_rates=$(echo "$send_line" | sed 's/.*=> *//')
            dest=$(echo "$dest_and_rates" | awk '{print $1}')
            send_rate=$(echo "$dest_and_rates" | awk '{print $2}')
            
            # 수신 정보 추출 (다음 라인에서)
            if [[ "$recv_line" =~ "<=" ]]; then
                recv_source=$(echo "$recv_line" | sed 's/^[ ]*//' | awk '{print $1}')
                recv_rate=$(echo "$recv_line" | sed 's/.*<= *//' | awk '{print $1}')
                
                # 값 검증
                if [[ -n "$send_rate" ]] && [[ "$send_rate" =~ [0-9] ]] && [[ -n "$recv_rate" ]] && [[ "$recv_rate" =~ [0-9] ]]; then
                    # Mbps로 변환
                    send_mbps=$(convert_to_mbps "$send_rate" 2>/dev/null)
                    recv_mbps=$(convert_to_mbps "$recv_rate" 2>/dev/null)
                    
                    # 변환 결과 검증
                    if [[ -n "$send_mbps" ]] && [[ -n "$recv_mbps" ]]; then
                        # 임계값 체크
                        send_check=$(echo "$send_mbps > $THRESHOLD" | bc -l 2>/dev/null || echo "0")
                        recv_check=$(echo "$recv_mbps > $THRESHOLD" | bc -l 2>/dev/null || echo "0")
                        
                        if [[ "$send_check" -eq 1 || "$recv_check" -eq 1 ]]; then
                            echo "[$TIMESTAMP] CONNECTION ALERT:" >> $LOGFILE
                            echo "  Source: $source" >> $LOGFILE
                            echo "  Destination: $recv_source" >> $LOGFILE
                            echo "  Send Rate: $send_rate (${send_mbps}Mbps)" >> $LOGFILE
                            echo "  Receive Rate: $recv_rate (${recv_mbps}Mbps)" >> $LOGFILE
                            echo "  --------------------------------" >> $LOGFILE
                            
                        fi
                    fi
                fi
            fi
        fi
    done
    
    # 임시 파일 정리
    rm -f /tmp/iftop_output.txt
    
    # 대기
    sleep $INTERVAL
done
