# 로컬 mTLS 앱 복원

기존 9개 서비스와 mTLS 경로를 사용하는 선택형 Docker 프로필입니다. 기존 실행 디렉터리에는 그 디렉터리를 생성한 실행기를 사용합니다. 복원 프로필은 새 디렉터리에서 시작해 해당 프로필에서 생성된 앱 상태를 한 번 전환합니다.

## 실행

저장소 루트에서 Docker Engine과 Compose를 실행한 상태로 아래 명령을 사용합니다. 런타임 이미지는 `linux/amd64`를 사용하므로 ARM 환경은 해당 플랫폼의 에뮬레이션을 준비하고 `DOCKER_DEFAULT_PLATFORM=linux/amd64`를 설정합니다.

```bash
python -m scripts.recoverable_mtls_runtime up --directory runtime/c02/app-recovery
python -m scripts.recoverable_mtls_runtime recover --directory runtime/c02/app-recovery
python -m scripts.recoverable_mtls_runtime status --directory runtime/c02/app-recovery
```

1. `recover`는 유지보수 상태를 저장해 기존 컨테이너의 재기동을 차단하고 수집기·앱·worker·watchdog를 정지합니다.
2. 네트워크가 차단된 작업 컨테이너가 원본 볼륨과 공개 소스 등록을 읽기 전용으로 열어 SQLite·Inbox·감사·사건·outbox의 암호화 백업을 생성합니다. 수집기 스풀과 읽기 전용 TLS 설정은 기존 볼륨을 유지합니다.
3. 작업 컨테이너는 백업을 격리된 임시 저장소에 복원하고 이전 세션을 회수합니다. 이력과 저장 계약을 대조한 뒤 별도 데이터 볼륨에 검증한 사본을 게시합니다. 서명된 승인 정보를 게시하면 앱·worker·watchdog가 승인된 경로로 기동하고 수집기가 전송을 재개합니다.
4. 중단되면 같은 디렉터리로 `recover`를 다시 실행합니다. 승인 전에는 유지보수 상태를 유지하며, 백업이 이미 완료됐으면 같은 암호화 백업을 재사용합니다. 기존 복원기의 1시간 체크포인트 유효기간을 적용합니다. 승인된 뒤에는 `up`이나 `recover`를 재실행해도 같은 복원 사본과 전환 이후에 기록된 상태를 사용합니다.

백업·서명 키는 전용 볼륨에 보관하고 실행 서비스에는 공개 승인 정보만 읽기 전용으로 마운트합니다. 이 프로필은 로컬 정비용이며 원본·백업·키가 있는 Docker 호스트의 손실에 대비하려면 별도 보관이 필요합니다. `down`은 프로젝트를 정지하고, `down --purge`는 이 프로젝트의 원본·복원·백업 볼륨도 삭제합니다.

## 재현

```bash
python -m scripts.test_recoverable_mtls_runtime --directory runtime/c02/app-recovery-check
```

새 테스트 프로젝트에서 복원 작업 프로세스를 JSONL 기록 중과 승인 게시 직전에 종료합니다. 기존 컨테이너 기동 차단, 같은 백업 재사용, 승인된 볼륨 기동, SQLite·Inbox·JSONL 이력과 접근 집행을 확인한 뒤 테스트 전용 리소스를 정리합니다. 결과는 테스트 디렉터리의 `verification.json`에 기록됩니다.
