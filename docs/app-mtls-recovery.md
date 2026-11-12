# 로컬 mTLS 앱 복원

기존 9개 서비스와 mTLS 경로를 사용하는 선택형 Docker 프로필입니다. 기존 실행 디렉터리에는 그 디렉터리를 생성한 실행기를 사용합니다. 복원 프로필은 새 디렉터리에서 시작해 해당 프로필에서 생성된 앱 상태를 한 번 전환합니다.

## 실행

저장소 루트에서 Docker Engine과 Compose를 실행한 상태로 아래 명령을 사용합니다. 런타임 이미지는 `linux/amd64`를 사용하므로 ARM 환경은 해당 플랫폼의 에뮬레이션을 준비하고 `DOCKER_DEFAULT_PLATFORM=linux/amd64`를 설정합니다.

먼저 `docker info`, `docker buildx version`, `docker compose version`이 성공하는지 확인합니다.
macOS에서 Homebrew 플러그인이 이미 설치돼 있는데 명령을 찾지 못하면 Docker 설정의
`cliPluginsExtraDirs`에 실제 플러그인 디렉터리가 포함돼 있는지 확인합니다.
설정 예시는 [Homebrew Buildx 안내](https://formulae.brew.sh/formula/docker-buildx)를 참고합니다.

```bash
python -m scripts.recoverable_mtls_runtime up --directory runtime/c02/app-recovery
python -m scripts.recoverable_mtls_runtime recover --directory runtime/c02/app-recovery
python -m scripts.recoverable_mtls_runtime status --directory runtime/c02/app-recovery
```

1. `recover`는 유지보수 상태를 저장해 기존 컨테이너의 재기동을 차단하고 수집기·앱·worker·watchdog를 정지합니다.
2. 네트워크가 차단된 작업 컨테이너가 원본 볼륨과 공개 소스 등록을 읽기 전용으로 열어 SQLite, Inbox, 감사, 사건, outbox와 정상 작업 기준선 및 승인 기록의 암호화 백업을 생성합니다. 수집기 스풀과 읽기 전용 TLS 설정은 기존 볼륨을 유지합니다.
3. 작업 컨테이너는 백업을 격리된 임시 저장소에 복원하고 이전 세션을 회수합니다. 이력과 저장 계약을 대조한 뒤 별도 데이터 볼륨에 검증한 사본을 게시합니다. 서명된 승인 정보를 게시하면 앱·worker·watchdog가 승인된 경로로 기동하고 수집기가 전송을 재개합니다.
4. 중단되면 같은 디렉터리로 `recover`를 다시 실행합니다. 승인 전에는 유지보수 상태를 유지하며, 백업이 이미 완료됐으면 같은 암호화 백업을 재사용합니다. 기존 복원기의 1시간 체크포인트 유효기간을 적용합니다. 승인된 뒤에는 `up`이나 `recover`를 재실행해도 같은 복원 사본과 전환 이후에 기록된 상태를 사용합니다.

백업·서명 키는 전용 볼륨에 보관하고 실행 서비스에는 공개 승인 정보만 읽기 전용으로 마운트합니다. 이 프로필은 로컬 정비용이며 원본·백업·키가 있는 Docker 호스트의 손실에 대비하려면 별도 보관이 필요합니다. `down`은 프로젝트를 정지하고, `down --purge`는 이 프로젝트의 원본·복원·백업 볼륨도 삭제합니다.

기준선과 승인 기록은 원본의 `/data/app-behavior-context.sqlite3`에서 복원 사본의
`/data/active/app-behavior-context.sqlite3`로 함께 이동합니다. 승인 취소와 이미 사용한 승인 횟수의
근거인 판정 기록도 보존하며, 재기동 시 서명한 기존 기록이 삭제되거나 바뀌지 않았는지 확인합니다.
원본에 이 DB가 없는 경우에는 격리 사본에만 빈 DB를 만듭니다. 별도 외부 경로로 설정한 DB를 누락한 채
복원을 진행하지 않습니다.

이 mTLS 실행기는 `BEHAVIOR_CONTEXT_DB_PATH`를 설정하지 않은 기본 경로를 사용합니다. 명시적인 경로는
원본, 임시 사본, 승인된 사본으로 바뀌는 작업 경로에 자동으로 다시 매핑하지 않습니다. 기존 설정을
검토하고 기본 경로를 사용하는 새 실행 디렉터리에서 재현합니다.

이 절차는 모든 기록자가 정상 종료한 정비 경계에서 실행합니다. 기준선 DB에 남은 `-journal`, `-wal`,
`-shm` 파일은 무시하지 않고 거부합니다. 비정상 종료로 남았다면 원래 애플리케이션의 SQLite 복구를 거친
후 정상 종료한 경계를 다시 준비해야 합니다. 원본을 수정하거나 파일을 임의로 지워 검사를 우회하지 않습니다.
정책 DB, 기준선 DB, 등록 파일과 JSONL 원본의 합계는 32 MiB 이하이며 최종 암호화 백업은 64 MiB
이하로 제한합니다. 한도를 초과하면 기록을 잘라내지 않고 백업을 거부합니다.

## 재현

```bash
python -m scripts.test_recoverable_mtls_runtime --directory runtime/c02/app-recovery-check
```

새 테스트 프로젝트에서 복원 작업 프로세스를 JSONL 기록 중과 승인 게시 직전에 종료합니다. 기존 컨테이너 기동 차단, 같은 백업 재사용, 승인된 볼륨 기동, SQLite·Inbox·JSONL 이력과 접근 집행을 확인한 뒤 테스트 전용 리소스를 정리합니다. 결과는 테스트 디렉터리의 `verification.json`에 기록됩니다.

복원 테스트에는 기준선, 승인, 승인 사용 판정, 승인 취소의 합성 저장 기록 4개를 넣고, 복원 전후의
기록 수와 해시를 대조합니다. 이 fixture는 비어 있지 않은 기록의 보존을 확인하기 위한 자료입니다.
실제 서명 검증과 정상 또는 위협 판정은 별도의 API 통합 테스트에서 확인합니다.

2026-11-10 로컬 검증에서는 mTLS 시험 13개와 별도 전체 상태 시험 25개가 모두 통과했습니다.
mTLS에서는 중간 장애 복구, 이력 보존, 기존 토큰의 403, 새 승인 토큰의 200, 수집기와 worker의
전송 재개를 확인했습니다. 별도 전체 상태 시험은 고정 시계에서 기존 토큰 3개가 만료 전에
회수로 거부되는지 확인합니다. 테스트 종료 후 해당 컨테이너, 볼륨, 네트워크는 남지 않았습니다.
기록은 다음 경로에 보관합니다.

- `runtime/c02/behavior-context-recovery-check-20261110-r2/verification.json`
- `runtime/week3/behavior-context-full-recovery-20261110-r2/verification.json`

두 실행은 같은 애플리케이션과 복구 로직을 검증했습니다. 전체 상태 시험의 재시도에서는
시험 실행기의 준비 대기를 30초에서 90초로 늘리고 시작 실패의 제한된 오류 코드를 기록하도록
보완했습니다. 따라서 두 실행의 이미지 ID는 다릅니다. 이 결과는 통제된 로컬 복구 검증이며
공개 자료의 탐지 정확도 또는 운영 환경의 복구 시간 보장을 뜻하지 않습니다.
