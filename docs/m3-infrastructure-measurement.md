# M3 인프라 재현과 반복 측정

2026년 11월 3일 · 인프라 담당 작업 브랜치 `feature/chaeheeju-m3-infra-validation` · 기준 `aitest` 병합 커밋 `82285c6`.

동료의 [PR #1](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/pull/1)에 포함된 내구 수신함·worker·관련 세션 회수를 재사용해 Windows/Docker 재현, 실행 경계, 반복 측정과 원자료를 추가한다. 이 대화의 로컬 도구로 실행했으며 팀원의 별도 재검토를 완료했다고 기록하지 않는다. 기존 백엔드와 탐지 정책을 다시 구현하거나 Sigma 규칙·임계값·개선 전 평가 데이터를 바꾸지 않는다.

## 변경 전후와 신뢰 경계

| 항목 | 변경 전 | 이번 변경 |
|---|---|---|
| Windows 회귀 | 공개 파일에도 POSIX 모드0644/0755를 요구해 524건 중 2건 실패 | POSIX에서 모드 비트를 검사하고 모든 환경에서 공개키 내용·서명·비밀값 비노출을 검사 |
| 시험용 개인키 | POSIX0600을 지정해 호스트 PEM 파일로 저장 | 서명 키를 프로세스 메모리에서만 사용하며 개인키 파일을 생성하지 않음 |
| worker 네트워크 | Compose 기본 네트워크 참여, 포트 미게시 | `network_mode: none`, 포트 없음, 실제 인터페이스가 loopback뿐인지 검사 |
| 자원·조건 | 기능 시연 원자료 | 서비스당 CPU1·메모리256MiB·PID128, 격리된 볼륨으로 3회 반복하는 측정 프로필 |
| 짧은 지연 | 기존 기능 실행기의 Windows monotonic 시계는 15.625ms 해상도 | 측정 실행기만 `perf_counter` 사용, 실제 구현·해상도도 원자료에 기록 |
| 빌드 입력 | 사용자 압축본이 빌드 문맥에 포함될 수 있음 | `.dockerignore`에 ZIP 제외 추가. 원본 압축본은 보존 |
| Windows 빌드 실행 모드 | Docker로 복사한 모듈 스크립트가 실행 가능 파일로 보여 Ruff EXE002 실패 | 테스트 이미지에서 모듈은0644, shebang 수집기는0755로 정규화 |

worker는 API와 통신하지 않고 공유 SQLite와 읽기 전용 공개키 등록을 사용한다. 네트워크 제거 후에도 접수·회수·중복 방지·재시작 시나리오가 동작하는지 확인한다. 독립 서비스 신원·mTLS·별도 업무 PEP를 구현했다는 뜻은 아니다.

| 실행 주체 | 네트워크·키 | 저장·권한 |
|---|---|---|
| API | 호스트 loopback 게시, 등록 공개키만 사용 | UID10001, 읽기 전용 루트, capability 제거, `/data` SQLite 쓰기 |
| worker | 외부 인터페이스·게시 포트 없음, 등록 공개키만 사용 | API와 같은 합성 시험 볼륨, 같은 UID, 읽기 전용 루트·capability 제거 |
| 호스트 시험 수집기 | 별도 서명 키를 메모리에서만 사용, loopback API 호출 | 공개키 등록 JSON만 컨테이너에 읽기 전용 제공 |

공유 DB·공유 UID 구조의 저장 권한 분리는 아직 운영 서비스 수준이 아니다. 이번 API 인증 비활성은 기존 local 합성 시험 설정이며 실제 사용자 로그인·IdP·EDR 인증을 검증하지 않는다. 관측은 접근을 제한하는 근거이고 MFA 성공·새 허용·회수 해제의 근거로 사용하지 않는다.

## 실행과 정리

Docker 엔진과 기존 개발 가상환경을 준비한 뒤 저장소 루트에서 실행한다. AWS·유료 모델 호출·실계정 변경은 없다.

```powershell
python -m scripts.measure_signal_infrastructure --repeats 3
python -m pytest -q
python -m ruff check .
```

실행기는 고유한 `secops-m3check-infra-*` 프로젝트와 이미지 태그를 만들고 각 반복에 새 볼륨·키·공개 등록을 사용한다. 앱 이미지는 첫 반복에서 한 번 빌드하고 같은 이미지 ID로 나머지를 실행한다. worker poll 주기는 기존 기능 시연 프로필의 0.05초이며 운영 기본값 0.5초와 구분한다.

각 반복 종료 시 해당 프로젝트의 컨테이너·네트워크·합성 볼륨을 정리한다. 마지막에는 이번 실행의 고유 이미지 태그를 제거한다. 실패한 실행도 실패 코드·부분 결과·정리 상태를 남긴다. 다른 작업의 컨테이너·볼륨·이미지를 정리하거나 host 전체 prune을 실행하지 않는다.

`runtime/m3-validation/infra-*/`에 전체 `measurement.json`, 반복별 `report.json`, `resource-samples.jsonl`, 빌드·Compose 명령 로그를 남긴다. 이 폴더는 Git/이미지에서 제외한다. 명령 출력이나 HTTP 본문에 개인키·서명·원문 허용 토큰을 복사하지 않는다.

## 측정 구간과 판정

| 구간 | 실제 관측 | 해석 제한 |
|---|---|---|
| 클라이언트 POST 시작부터 최초403 확인 | 고해상도 시계, 관련 첫 세션의 `SESSION_NOT_AUTHORIZED` 확인까지 | 영수증 polling 간격·검사 클라이언트 요청 시간을 포함한 관측 상한. 실제 공격 발생 시점부터의 지연 아님 |
| 서버 접수부터 완료 | 영수증 `received_at`과 `completed_at`의 차이 | 대기·재시도 포함. worker CPU 실행 시간 아님 |
| 정상 처리 | worker를 실행한 상태의 첫 위험 관측, 반복당 1건 | 3건. 대규모 위협·사용자 표본이 아님 |
| 의도적 중단 | worker 중지 후 접수, 앱 재시작, worker 재개, 회수 확인 | 정상 지연과 섞지 않음. 시험이 만든 중단 기간을 포함하며 RTO가 아님 |
| HTTP | 작업 종류·기대 상태별로 따로 집계 | 영수증 조회·세션 이력 조회를 독립 회수 표본으로 세지 않음 |
| CPU·메모리·네트워크·블록I/O·PID | 해당 프로젝트의 두 컨테이너만 Docker CLI로 표본 수집 | 표시값은 반올림됨. Linux 메모리는 CLI의 cache 차감 방식. I/O 누적값을 디스크 사용량이나 IOPS로 표현하지 않음 |
| 시작 | 이미지 준비 후 Compose 시작부터 최초 live 응답 | 이미지 pull을 포함한 cold-start나 서비스 복구 목표 아님 |

P50/P95는 nearest-rank 경험 분위수다. 3건의 P95는 최대값이며 기업 모집단의 P95·신뢰구간이나 SLA 보장이 아니다. 시계 해상도는 실제 측정 정확도와 다르다. 자원 표본은 주기 사이의 최대 순간을 놓칠 수 있으므로 표본에서 관찰한 최대값으로만 해석한다.

기능 통과와 계측 자료 수집의 완전성을 확인하지만 측정 후 새 성능 합격선을 만들지 않는다. 본 실행은 부하 시험이 아니며 Windows pytest·Docker 테스트 이미지 작업을 병행한 개발 호스트의 결과다. 정상 부하·동시성별 처리량, 저장 실패 주입의 운영 영향, 서비스 통신 단절, 백업·복원 및 RTO/RPO 목표 검증은 후속 작업이다.

## 실제 결과와 재현 원자료

[최종 결과](m3-infrastructure-results.md): Windows·Linux Docker 각각 전체545건 통과, Compose12개 기능 검사×3회=36회 통과, 자원 표본56개를 기록했다. [공유 JSON 원자료](infrastructure-results/m3-windows-20261103.json)에 반복별 시간·상태·보안 설정·소스 지문을 보존했다. 최초524건 중2건 실패와 첫 기본 시계 측정 기록은 로컬 원자료에 보존하고 최종 성공과 혼합하지 않는다. 독립 팀원 검토, C03 스캐너 비교, M4 GuardDuty와 I2 서비스 인증은 이번 작업의 완료 항목으로 표시하지 않는다.

## 근거

- [Python 3.12 os.chmod](https://docs.python.org/3.12/library/os.html#os.chmod): Windows에서는 POSIX 권한 비트 전체를 구현하지 않음.
- [Python 3.12 perf_counter](https://docs.python.org/3.12/library/time.html#time.perf_counter): 짧은 시간 측정용 고해상도 단조 시계.
- [Docker stats](https://docs.docker.com/reference/cli/docker/container/stats/): CLI 자원 표본·Linux cache 차감·프로세스와 스레드의 PID 의미.
- [Docker none network](https://docs.docker.com/engine/network/drivers/none/): loopback만 제공하는 네트워크 경계.
- [기존 M3 계약](m3-durable-signals.md), [이전 macOS/Linux 실행 기록](m3-docker-validation.md), [담당자 브랜치·PR 절차](contribution-workflow.md).
