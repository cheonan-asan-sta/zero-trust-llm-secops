# M3/I1 로컬 구현 검증 결과

검증일: 2026년 11월 2일. 작업 브랜치 `feature/m3-durable-signals`, 시작 커밋
`71cbfc0812fe9a33cbbbf6f490638ad0361c2d6a`. 아래 결과는 해당 브랜치 변경의 로컬 실행 기록이다.
실제 IdP·EDR·GuardDuty·AWS·유료 모델을 호출하지 않았다.

후속 실제 Docker 검증에서는 앱·worker 이미지 빌드와 Compose HTTP·저장·재시작 시나리오
11개를 통과했다. 테스트 이미지 내부의 전체 524건·의존성 경고 2건과 Ruff 통과를 확인했다.
환경·이미지 지문·원자료·실행 유지 상태는 [Docker 검증 기록](m3-docker-validation.md)을 따른다.

## 실행 결과

아래 macOS 518건은 최초 구현 검증 시점의 기록이다. 이후 실행 검증기 자체 시험 6건을 추가했다.

| 환경·검사 | 결과 |
|---|---|
| macOS arm64 / Python 3.12.13, CI와 같은 Python 부버전 | 전체 518건 통과, 실패·오류·건너뜀 0, 의존성 경고 2 |
| macOS arm64 / Python 3.14.8 | 전체 518건 통과, 실패·오류·건너뜀 0, 의존성 경고 1 |
| Ruff | 통과 |
| `git diff --check` | 통과 |
| `docker-compose -f compose.yaml -f compose.signals.yaml config --quiet` | 통과 |
| 최초 Docker 검사 | 당시 daemon이 없어 구성 검사만 수행, 아래 후속 실기동과 구분 |
| 후속 Docker 앱·worker 빌드/실기동 | 성공, 실제 Compose 시나리오 11개 통과 |
| 후속 Docker 컨테이너 내부 회귀시험 | 524건 통과·의존성 경고 2건, Ruff 통과 |

최초 구현 검증은 기존 421건에 신규 97건을 추가했다. 신규 시험은 정책·서명 38건, 수신함 32건,
HTTP/API 19건, 별도 worker 프로세스 8건이다. 경고는 Starlette TestClient/httpx 사용 중단
안내와 Python 3.12의 Mangum 이벤트 루프 사용 중단 안내이며 실패로 숨기지 않았다.
Python 3.12의 전체 실행은 8.59초, 3.14는 7.35초였다. 이는 테스트 실행 시간이며
운영 처리량·접근 지연·RTO/RPO 측정값이 아니다.

## 확인한 핵심 동작

- 저장 commit 실패에는 접수 성공을 반환하지 않는다. 접수 상태는 새 프로세스에서도 조회된다.
- 같은 테넌트·이벤트의 동일 재전송은 중복 적용하지 않고, 다른 내용은 409로 거부한다.
- 인증·기기 관찰의 종류·주체 권한과 서명을 검사한다. 관찰 전용 source의 전체 세션 증명
  경로 우회와 같은 테넌트 내 출처 간 공개키 공유도 차단한다.
- 관련 사용자 또는 기기의 세션만 제한한다. 관련 세션 두 개의 기존 허용은 다음 HTTP 접근에서
  403이고, 무관 사용자 세션은 200이다. 다른 테넌트의 세션은 변경하지 않는다.
- 순서가 뒤집힌 위험 신호는 제한을 강화할 수 있지만 정상 신호는 기존 제한을 해제하지 않는다.
  후속 동기 평가와 새 세션도 기존 위험 제한을 우회하지 못한다.
- 실제 별도 Python 프로세스를 정책 반영 직전·직후 `os._exit(73)`으로 종료했다.
  lease 만료 후 새 프로세스가 복구하며 이미 반영된 세션 버전·이력을 중복 증가시키지 않는다.
- 마지막 처리 시도의 완료 기록이 유실된 경우에도 기존 저널 효과를 읽어 완료 상태를 복구한다.
  그 사이 출처가 폐기돼도 이미 반영된 효과의 조회만 허용하며 새 정책 효과를 만들지 않는다.
  효과가 없다면 추가 정책 시도 없이 `PROCESSING_EXHAUSTED`로 실패 보관한다.
- 일시 장애는 재시도하고, 영구 장애·상한 초과·손상·권한 부족은 각각 실패 또는 거부 상태로 남긴다.
- production에서는 새 HTTP 경로가 404이고 worker는 저장소를 만들기 전에 실행을 거부한다.

## 재현과 원자료

```sh
python -m pytest -q --junitxml=runtime/m3-validation/pytest.xml
python -m ruff check .
SIGNAL_REGISTRY_PATH=/absolute/path/to/public-sources.json \
  docker-compose -f compose.yaml -f compose.signals.yaml config --quiet
```

이번 로컬 실행의 JUnit 원자료는 `runtime/m3-validation/pytest-python312.xml`과
`runtime/m3-validation/pytest-python314.xml`에 있다. 실행 생성물은 Git에서 제외한다.
입력·응답·오류 계약, 역할별 인계, CLI와 M6/M7 평가 준비는
[구현 명세](m3-durable-signals.md)를 따른다.
Docker 후속 실행 원자료는 `runtime/m3-validation/compose-actual-2.json`,
`docker-environment.json`, `docker-tests.log` 등에 분리해 보존한다.

신규 공개 원본·독립 라벨 검토·실제 모델 비교, 채희주의 인프라 실행/측정,
안전한 제한 해제·복구 절차, 독립 업무 PEP 및 멘토 최종 수용은 별도 후속 과제다.
