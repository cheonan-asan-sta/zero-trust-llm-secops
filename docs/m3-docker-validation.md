# M3/I1 실제 Docker 검증 기록

2026년 11월 2일 검증. 로컬 앱·worker 이미지를 빌드하고 Compose에서 별도 컨테이너로 실행했다. 실제 HTTP·저장·재시작 시나리오 **11개를 통과**했으며, 별도 테스트 이미지 안에서 **524건 통과·경고 2건과 Ruff 통과**를 확인했다. 최초 macOS 검증 때의 Docker 미실행 기록은 [이전 검증 기록](m3-validation-results.md)에 보존한다.

## 환경과 소스 기준

| 항목 | 실제 확인한 값 |
|---|---|
| 호스트 | macOS arm64 |
| 로컬 VM | Colima 0.10.3, `secops-m3`, VZ, CPU 2개·메모리 3GiB·OS 디스크 20GiB·데이터 디스크 12GiB |
| Docker client / server | 29.6.2 / 29.5.2, server Linux arm64, API 1.54 |
| Linux kernel | `6.8.0-117-generic` |
| Compose / Buildx | 5.3.1 / 0.37.2 Homebrew |
| 컨테이너 Python | 3.12.16 |
| Git 기준 | `feature/m3-durable-signals`, 시작 커밋 `71cbfc0812fe9a33cbbbf6f490638ad0361c2d6a` 기반 M3 변경 |
| 실행 소스 확인 | 호스트와 실행 이미지의 앱·worker Python 파일 39개의 SHA-256 일치 |
| Compose project | `secops-m3check-d9d683fb4992` |
| 실제 HTTP 실행 구간 | 2026-11-02 16:10:43~16:10:48 KST, 원자료 시각은 UTC |
| 종료 시 서비스 상태 | app `healthy`, worker 실행 중, `http://127.0.0.1:59210` |

기본 Docker context는 `default`로 유지했다. 실행 대상은 `DOCKER_HOST`로 별도 엔진을 지정했으며 사용자 Docker 설정 파일은 수정하지 않았다. CLI 플러그인 경로는 프로젝트의 `runtime/m3-validation/docker-cli/config.json`에 설정했다. VM 호스트 공유는 ASCII 경로 `/private/tmp/secops-m3-public`만 읽기 전용으로 허용했고 개인키가 있는 호스트 디렉터리를 공유하지 않았다.

검증에 사용한 로컬 이미지 식별자는 다음과 같다. `image inspect`의 `RepoDigests`에도 각각 같은 지문이 기록됐지만, 이번 작업에서 원격 레지스트리에 이미지를 게시한 것은 아니다.

| 역할·태그 | 이미지 ID |
|---|---|
| 앱·worker, `zero-trust-llm-secops:local` | `sha256:e764bec97c0485433c4c4287ef1a76866538dd80ef06583c8d4ec43b71a26037` |
| 회귀시험, `zero-trust-llm-secops:m3-tests` | `sha256:c1a31b37c40b4219bb4b35c950e80c3757064136e1e32e7c277f4bae2ed98090` |

Docker 실행을 위해 [Dockerfile](../Dockerfile)에 worker 스크립트를 포함했고, [Compose overlay](../compose.signals.yaml)에 공통 SQLite 볼륨·읽기 전용 공개키 등록 마운트를 정의했다. [실행 검증기](../scripts/test_signal_compose.py)와 [검증기 자체 시험](../tests/test_signal_compose_runner.py)을 추가했으며 [테스트 이미지](../Dockerfile.test)에도 overlay를 포함했다. 검증기 자체 시험 6건이 추가되어 최초 518건에서 524건으로 늘었다. 기존 Sigma 규칙·임계값·개선 전 평가 결과는 변경하지 않았다.

## 실제 Compose 검증

최종 보고서 `runtime/m3-validation/compose-actual-2.json`의 `status`는 `passed`다. 아래 항목은 모두 실제 앱·worker 컨테이너를 대상으로 실행했다.

| 검증 항목 | 관찰 결과 |
|---|---|
| `container_boundaries` | 두 서비스 UID 10001. 앱이 공개키 등록을 읽고, 앱·worker가 같은 영속 볼륨의 서로 작성한 자료를 확인. 공유된 신호 경로에 개인키 없음 |
| `normal_probe` | 정상 서명 세션의 모의 업무 접근 HTTP 200 |
| `related_revoked` | 위험 관측 후 관련 세션 2개가 `REVOKED`·버전 2, 기존 허용으로 다음 HTTP 접근 403 |
| `unrelated_preserved` | 무관한 사용자 세션은 `ACTIVE`·버전 1, 접근 200 |
| `duplicate_idempotent` | 같은 서명 관측 재전송은 중복 영수증을 반환하며 정책 효과·세션 버전이 증가하지 않음 |
| `conflicting_payload_rejected` | 같은 이벤트 ID에 다른 서명 내용은 HTTP 409 |
| `pending_survives_app_restart` | worker 중지 중 접수한 pending 영수증이 앱 재시작 후 유지 |
| `worker_resumes_pending` | worker 재개 후 해당 영수증이 completed로 전환, 관련 세션 회수 |
| `restarts_preserve_receipt_and_versions` | 앱·worker 재시작 후 접수/완료 시각·시도 횟수·정책 버전 보존 |
| `unused_grant_remains_revoked` | 재시작 전에 소비하지 않았던 기존 허용도 회수된 세션에서는 접근 403 |
| `unrelated_survives_restarts` | 재시작 뒤에도 무관 세션은 버전 1·허용 상태 유지, 접근 200 |

첫 위험 관측은 접수 `07:10:45.357188Z`, 완료 `07:10:45.362938Z`로 관련 세션 2개를 변경했다. 두 번째는 worker 중지 상태에서 `07:10:45.671401Z`에 접수됐고 재개 후 `07:10:47.628739Z`에 완료됐다. 이후 두 서비스를 재시작해도 두 번째 영수증의 접수·완료 시각과 `attempts=1`이 같았다. 이 두 건은 기능 시연의 관찰값이며 처리량·P95·RTO/RPO 성능의 증거로 일반화하지 않는다.

환경 원자료에서는 두 컨테이너가 `secops` 사용자, 읽기 전용 루트 파일시스템, `cap_drop=ALL`로 실행됨을 확인했다. `/data`는 같은 쓰기 가능한 볼륨이고 `/signals/sources.json`은 읽기 전용 bind다. 공개 등록 파일은 `0644`로 비관리자 계정이 읽을 수 있었다. 앱 포트는 `127.0.0.1:59210`으로만 게시하고 worker 포트는 게시하지 않았다.

추가 HTTP 확인은 `/` 200, `/health/live` 200·`ok`, `/health/ready` 200·`ready`였다. readiness의 수신함 무결성은 `ok`·검증된 영수증 2건이다. **서비스 readiness 통과는 탐지 품질 목표 달성을 뜻하지 않는다.** 기존 holdout 탐지 품질 게이트 미달 결과는 그대로다.

## 컨테이너 내부 회귀시험

`Dockerfile.test`로 빌드한 테스트 이미지를 실제 Docker 엔진에서 실행했다.

```text
Ruff: All checks passed!
pytest: 524 passed, 2 warnings in 8.19s
```

경고 2건은 Starlette TestClient/httpx와 Mangum 이벤트 루프의 사용 중단 안내다. 8.19초는 전체 테스트 실행 시간이며 업무 접근 지연이나 부하 성능이 아니다. Python 프로세스의 정책 반영 직전·직후 강제 종료 시험은 이 회귀시험의 `test_signal_worker_process.py`에 포함된다. 위 Compose 검증 11개 자체가 모든 종료 시점의 race를 검증했다는 뜻은 아니다.

## 초기 실패와 조치

첫 시도는 `compose_up_exit_1`로 실패했고 기능 검증 항목을 실행하지 못했다. 한글·공백이 포함된 프로젝트 경로를 Lima의 fstab이 escape 없이 기록해 virtiofs 공유가 마운트되지 않았고, VM에서 공개키 bind 원본을 찾을 수 없었다. 이 결과는 `compose-initial-mount-failure.json`에 보존했다.

별도 `secops-m3` VM의 OS 구성을 재생성하면서 데이터 디스크는 보존했다. 공유 대상을 `/private/tmp/secops-m3-public`의 공개키 JSON만으로 줄이고 `--registry-directory`로 전달한 뒤 최종 11개 시나리오를 통과했다. 개인키는 호스트의 접근 제한 디렉터리에 남겼으며 컨테이너에 마운트하지 않았다. 초기 실패와 최종 성공을 같은 실행 결과로 합치지 않는다.

## 재현과 원자료

팀원이 새로 clone한 저장소에서는 Docker 엔진을 준비한 뒤 저장소 루트에서 다음을 실행한다. 기본 동작은 이미지 빌드·독립 Compose 검증·자원 정리다.

```sh
python -m pip install -e '.[dev]'
python -m scripts.test_signal_compose --report runtime/m3-validation/compose-report.json
```

macOS Colima에서 ASCII 공유 경로가 필요하면 VM에 읽기 전용으로 공유한 경로를 `--registry-directory /private/tmp/secops-m3-public`처럼 추가한다. 공유 경로에는 공개키 JSON만 복사하며 개인키 디렉터리는 공유하지 않는다.
기존 DB와 분리한 로컬 DB를 사용한다. 새 `observation` journal 기록은 이전 코드와 호환되지 않아 코드만 되돌릴 수 없으며, 기존 DB 업그레이드 전에는 정책·키·감사를 포함한 일관된 스냅샷이 필요하다. 옛 백업으로 회수 상태를 되살리는 복원은 금지하며 운영 복원·롤백 절차는 미구현이다.

이 호스트의 프로젝트 루트에서 동일한 로컬 엔진을 사용하려면 환경 선택 파일을 먼저 읽는다. 이 파일은 실행 시 생성한 로컬 설정이며 Git에 포함하지 않는다. 다른 호스트에서는 자신의 Docker 엔진·공개 파일 공유 경로를 먼저 준비해야 한다.

```sh
source runtime/m3-validation/docker-env.sh

docker build -t zero-trust-llm-secops:local -f Dockerfile .
python -m scripts.test_signal_compose \
  --registry-directory /private/tmp/secops-m3-public \
  --report runtime/m3-validation/compose-reproduction.json \
  --no-build

docker build -t zero-trust-llm-secops:m3-tests -f Dockerfile.test .
docker run --rm zero-trust-llm-secops:m3-tests
```

최종 실증에는 `--keep-running`도 사용해 앱·worker·합성 데이터 볼륨을 유지했다. 위 재현 예시는 기본 정리 동작을 사용하며 이번 실증과 다른 고유 project·임의 포트를 만든다. 실제 유지된 서비스의 이름·포트는 위 환경 표를 따른다. 검증 결과의 `cleanup`은 자원을 유지했다고 기록했으므로 컨테이너를 정리했다고 보고하지 않는다.

| 로컬 원자료 | 내용 |
|---|---|
| `runtime/m3-validation/compose-actual-2.json` | 통과 11개 항목, HTTP 상태, 세션·영수증·재시작 결과, 자원 유지 상태 |
| `runtime/m3-validation/docker-environment.json` | 실제 엔진·이미지·컨테이너 보안 설정·실행 Python 파일 39개 지문 |
| `runtime/m3-validation/docker-app.log`, `docker-worker.log` | 앱·worker 실행 로그 |
| `runtime/m3-validation/docker-tests-build.log`, `docker-tests.log` | 테스트 이미지 빌드와 컨테이너 내부 Ruff·pytest 결과 |
| `runtime/m3-validation/compose-initial-mount-failure.json` | 최초 마운트 실패 기록 |

`runtime/m3-validation/`은 Git에서 제외하며 `.dockerignore`도 `runtime`을 제외한다. 실행기에서 만든 호스트 개인키와 로컬 설정을 저장소나 이미지에 포함하지 않는다. 원자료를 별도로 공유할 때도 공개 보고서·로그와 개인키를 구분한다.

이번 결과는 로컬 단일 호스트·공유 SQLite·합성 서명 신호 범위다. 실제 IdP/EDR·GuardDuty, mTLS·독립 업무 PEP, 외부 SIEM/ITSM·AWS 배포·유료 모델 호출은 수행하지 않았다. 신규 공개 데이터·독립 라벨·M6 모델 비교, 운영 부하·백업 복원·RTO/RPO 실측과 팀원의 별도 환경 재현은 후속 작업이다. 이미지는 원격 레지스트리에 게시하지 않았다.
