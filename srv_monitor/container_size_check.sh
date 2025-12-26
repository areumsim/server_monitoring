# Docker Container들의 물리적 디스크 사용량을 확인하는 스크립트
# 1. 모든 컨테이너 레이어 크기를 확인 시 인자없이 실행 `./container_size_check.sh`
# 2. 특정 컨테이너 구체적인 하위 레이어 크기 확인 시 컨테이너 이름을 인자로 실행 `./container_size_check.sh {container_name}`

#!/bin/bash

# 사용법 출력 함수
usage() {
  echo "Usage: $0 [container_name]"
  echo "If container_name is provided, will show subdirectory sizes for that container"
  exit 1
}

# overlay2 디렉토리 경로
OVERLAY2_DIR="/var/lib/docker/overlay2"
MOUNTS_DIR="/var/lib/docker/image/overlay2/layerdb/mounts"

# 특정 컨테이너 이름이 제공되었는지 확인
CONTAINER_NAME=$1

# 컨테이너별 layer 정보 출력
show_container_layers() {
  echo -e "Size\tContainer Name\tLayer ID"
  
  # du 명령으로 overlay2 내 디렉토리별 크기 측정 후 정렬
  du -sh ${OVERLAY2_DIR}/* | sort -hr | while read SIZE DIR; do
      # layer-id 추출
      LAYER_ID=$(basename "$DIR")
      
      # container mount-id 찾기
      CONTAINER_ID=$(grep -l "$LAYER_ID" "$MOUNTS_DIR"/*/mount-id | awk -F'/' '{print $(NF-1)}')
      
      # 컨테이너 이름 조회
      if [ -n "$CONTAINER_ID" ]; then
          NAME=$(docker inspect --format '{{.Name}}' "$CONTAINER_ID" 2>/dev/null | sed 's/^\/\| //g')
          if [ -z "$NAME" ]; then
              NAME="Unknown (Stopped or Deleted)"
          fi
          echo -e "$SIZE\t$NAME\t$LAYER_ID"
          
          # 특정 컨테이너의 하위 디렉토리 분석
          if [ -n "$CONTAINER_NAME" ] && [ "$NAME" = "$CONTAINER_NAME" ]; then
              echo -e "\nSubdirectories for container: $CONTAINER_NAME (Layer: $LAYER_ID)\n"
              
              # 마운트 포인트 확인
              MOUNT_POINT="${OVERLAY2_DIR}/${LAYER_ID}/merged"
              
              if [ -d "$MOUNT_POINT" ]; then
                  echo -e "Size\tPath"
                  # 하위 디렉토리 용량 확인 (첫 번째 수준만)
                  du -sh ${MOUNT_POINT}/* 2>/dev/null | sort -hr
              else
                  # merged 디렉토리가 없으면 diff 디렉토리 확인
                  DIFF_DIR="${OVERLAY2_DIR}/${LAYER_ID}/diff"
                  if [ -d "$DIFF_DIR" ]; then
                      echo -e "Size\tPath"
                      du -sh ${DIFF_DIR}/* 2>/dev/null | sort -hr
                  else
                      echo "Cannot access container's filesystem layers"
                  fi
              fi
              break
          fi
      fi
  done
}

# 메인 로직
if [ -z "$CONTAINER_NAME" ]; then
  show_container_layers
else
  show_container_layers "$CONTAINER_NAME"
fi