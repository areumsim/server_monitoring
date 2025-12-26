"""
Label Studio 프로젝트 전체 백업 스크립트

[개요]
Label Studio에 등록된 모든 프로젝트의 어노테이션 데이터를
JSON 또는 YOLO 형식으로 일괄 내보내기(Export)하는 자동화 스크립트.
데이터 라벨링 작업 결과물을 정기적으로 백업하기 위한 용도.

[Label Studio란?]
- 오픈소스 데이터 라벨링 플랫폼 (https://labelstud.io)
- 이미지, 텍스트, 오디오 등 다양한 데이터에 어노테이션 작업 가능
- 머신러닝 모델 학습용 데이터셋 생성에 사용

[사전 요구사항]
1. Label Studio SDK 설치: pip install label-studio-sdk
2. Label Studio 서버가 실행 중이어야 함
3. API 토큰 발급 필요 (Label Studio 웹 UI > Account & Settings > Access Token)

[cron 자동 실행 설정 예시]
매일 새벽 3시에 백업 실행:
    0 3 * * * /opt/scripts/label_backup_wrapper.sh

[출력 구조]
export_{타임스탬프}/
├── {프로젝트ID}_{프로젝트명}/
│   └── 내보내기된 JSON 또는 YOLO 파일들
├── {프로젝트ID}_{프로젝트명}/
│   └── ...
"""

from label_studio_sdk import Client
import os
from datetime import datetime

# =============================================================================
# 설정 영역 - 환경에 맞게 수정 필요
# =============================================================================

# Label Studio 서버 주소
# - 사내 서버에서 운영 중인 Label Studio 인스턴스
# - 포트 7050: 메인 Label Studio 서버
# - 포트 7090: 백업/테스트용 서버 (필요시 사용)
host = 'http://###.###.###.###:7050'

# Label Studio API 토큰
# - 발급 방법: Label Studio 웹 UI 로그인 > 우측 상단 프로필 > Account & Settings > Access Token
# - 토큰은 40자리 영숫자 문자열 형태
# - 보안 주의: 이 토큰으로 모든 프로젝트에 접근 가능하므로 외부 노출 금지
api_key = '########################################'

# 내보내기 형식
# - 'JSON': Label Studio 기본 JSON 형식 (모든 메타데이터 포함)
# - 'YOLO': YOLO 객체 탐지 모델 학습용 형식 (이미지 + txt 라벨)
# - 'COCO': COCO 데이터셋 형식
# - 'VOC': Pascal VOC XML 형식
export_type = 'JSON'

# 백업 파일 저장 경로
# - 내보내기 결과물이 저장될 기본 디렉토리
# - 실행 시 export_{타임스탬프}/ 하위 폴더가 자동 생성됨
base_output_dir = '/home/user/arsim/opt_script'

# =============================================================================
# 유틸리티 함수
# =============================================================================

def is_ascii(s):
    """문자열이 ASCII 문자로만 구성되어 있는지 확인"""
    return all(ord(c) < 128 for c in s)

# =============================================================================
# 메인 로직
# =============================================================================

def main():
    """
    Label Studio의 모든 프로젝트를 순회하며 내보내기 수행

    처리 순서:
    1. Label Studio 서버에 API 연결
    2. 등록된 모든 프로젝트 목록 조회
    3. 타임스탬프 기반 출력 디렉토리 생성
    4. 각 프로젝트별로 지정된 형식으로 내보내기
    5. 결과 로그 출력
    """

    # Label Studio 클라이언트 초기화 및 서버 연결
    ls = Client(url=host, api_key=api_key)

    # 전체 프로젝트 목록 조회
    projects = ls.list_projects()
    print(f"총 {len(projects)} 개의 프로젝트를 찾았습니다.")

    # 백업 폴더 생성 (타임스탬프로 중복 방지)
    # 예: export_20250328_153559/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    main_output_dir = os.path.join(base_output_dir, f"export_{timestamp}")
    os.makedirs(main_output_dir, exist_ok=True)

    # 각 프로젝트 순회하며 내보내기
    for project in projects:
        project_id = project.id
        project_title = project.title

        # 폴더명에 사용할 수 없는 특수문자 제거
        # 예: "프로젝트 #1 (테스트)" → "프로젝트__1__테스트_"
        safe_title = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in project_title)

        print(f"\n프로젝트 내보내기 시작: {project_title} (ID: {project_id})")

        # 프로젝트별 하위 폴더 생성
        # 예: export_20250328_153559/3_Open_Data_Portal/
        project_output_dir = os.path.join(main_output_dir, f"{project_id}_{safe_title}")
        os.makedirs(project_output_dir, exist_ok=True)

        try:
            # 프로젝트의 모든 어노테이션 데이터 내보내기
            result = project.export(export_type=export_type, output_dir=project_output_dir)

            print(f"내보내기 완료: {result['filename']}")
            print(f"상태: {result['status']}, 내보내기 ID: {result['export_id']}")

        except Exception as e:
            # 개별 프로젝트 실패 시에도 다른 프로젝트는 계속 처리
            print(f"프로젝트 {project_title} (ID: {project_id}) 내보내기 중 오류 발생: {str(e)}")

    print(f"\n모든 프로젝트 내보내기 완료. 결과물 위치: {main_output_dir}")

if __name__ == "__main__":
    main()
