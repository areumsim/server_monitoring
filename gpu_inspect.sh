#!/bin/bash
# gpu_inspect.sh
# GPU를 사용 중인 프로세스 → 컨테이너 이름, 이미지, 실행 중인 스크립트 경로까지 추적

echo "🔍 [GPU 사용 중 프로세스 → 컨테이너 매핑]"

# 1. nvidia-smi에서 GPU 사용하는 Python PID만 추출
pids=$(nvidia-smi | grep python | awk '{print $5}' | sort -u)

if [ -z "$pids" ]; then
  echo "✅ 현재 GPU를 점유 중인 Python 프로세스가 없습니다."
  exit 0
fi

# 2. 각 PID에 대해 컨테이너 ID / 이름 / 이미지 / 실행 중인 스크립트 경로 추적
for pid in $pids; do
  if [ ! -d /proc/$pid ]; then
    echo "⚠️ PID $pid: 프로세스 종료됨"
    continue
  fi

  cid=$(cat /proc/$pid/cgroup 2>/dev/null | grep "docker" | head -n 1 | sed 's|.*docker/||' | cut -d/ -f1)
  
  if [ -z "$cid" ]; then
    echo "❓ PID $pid: 컨테이너 소속 아님 (호스트에서 직접 실행됨)"
    continue
  fi

  # 도커 컨테이너 정보 가져오기
  info=$(docker ps --filter "id=$cid" --format "{{.ID}}|{{.Names}}|{{.Image}}")
  
  if [ -z "$info" ]; then
    echo "❌ PID $pid: 컨테이너 $cid (정보 없음, 중지되었거나 삭제됨)"
    continue
  fi

  container_id=$(echo $info | cut -d'|' -f1)
  container_name=$(echo $info | cut -d'|' -f2)
  image_name=$(echo $info | cut -d'|' -f3)

  # 실행 중인 Python 스크립트 경로
  script_path=$(readlink /proc/$pid/cwd 2>/dev/null)

  echo "📦 PID $pid | 🐳 Container: $container_name | 🖼 Image: $image_name"
  echo "    🔗 실행 위치: $script_path"
  echo "    🧠 명령줄: $(tr '\0' ' ' < /proc/$pid/cmdline)"
  echo "--------------------------------------------------"
done
