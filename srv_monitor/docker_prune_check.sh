# 미사용 docekr image, volume 확인하는 스크립트

docker images --format "{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}" | while read image image_id image_size; do
    # 해당 이미지를 사용하는 컨테이너 확인
    container_count=$(docker ps -a --filter "ancestor=$image_id" --format "{{.ID}}" | wc -l)
    
    # 사용 중이지 않은 이미지만 출력
    if [ "$container_count" -eq 0 ]; then
        echo -e "[미사용 이미지] $image (ID: $image_id, Size: $image_size)"
    fi
done

docker volume ls --format "{{.Name}} {{.Driver}}" | while read volume_name volume_driver; do
    # 해당 볼륨을 사용하는 컨테이너 확인
    container_count=$(docker ps -a --filter "volume=$volume_name" --format "{{.ID}}" | wc -l)

    # 사용 중이지 않은 볼륨만 출력
    if [ "$container_count" -eq 0 ]; then
        volume_size=$(du -sh "/var/lib/docker/volumes/$volume_name" 2>/dev/null | awk '{print $1}')
        echo "[미사용 볼륨] $volume_name (Driver: $volume_driver, Size: ${volume_size:-Unknown})"
    fi
done

