# DB 통신 교체의 관리 잠금과 실제 프로세스 중단 복구

2026-11-07 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.

[PR41 자동 교체](database-transport-rotation.md)의 후속이다. 기존에는 교체 실행기끼리 공통
잠금을 사용했지만 일반 시작·종료·정리 명령은 같은 잠금을 거치지 않았다. 실행 중 종료나
볼륨 정리가 교체와 겹치는 경계를 막고, 같은 프로세스 안에서 객체를 새로 만드는 시험을
실제 별도 호스트 프로세스의 강제 종료·새 프로세스 재개로 확장한다.

## 변경한 동작

| 작업 | 새 경계 |
|---|---|
| `up`, `down`, `down --purge` | 교체기와 같은 OS 잠금을 얻은 뒤 상태 읽기·Compose 생성·Docker 변경 |
| `tick`, `once`, `run`, `preflight` | 상태를 읽거나 Compose 파일을 다시 쓰기 전에 공통 잠금 획득 |
| `status` | 실행 중에도 최초 공개 anchor와 서명 이력을 검증해 조회. Compose·journal·환경 파일 수정 및 Docker 호출 없음 |
| 프로세스 종료 | OS가 기존 잠금을 해제. lock 파일 삭제나 새 후보 발급 없이 같은 journal·계획·서비스 ID로 재개 |
| 잘못된 journal | pause는 boolean, 다음 점검 시각은 유한한 음수 아닌 수만 허용. 임의 문자열·NaN·무한대 거부 |

`run`은 실행되는 동안 관리 잠금을 보유한다. 종료/정비하려면 먼저 해당 foreground 실행기를
정상 종료하고 `down`을 실행한다. 진행 중 교체는 기존처럼 `once/run`으로 먼저 재개한다.
명시적인 `--purge`는 실행기가 없을 때 해당 시험 자원을 폐기하는 기존 기능이며 복구가 아니다.
잠금이 바쁘다고 파일을 지우거나 자동으로 다른 경로/프로필을 만들지 않는다.

```powershell
.venv/Scripts/python.exe -m scripts.database_transport_runtime status --directory runtime/c02/my-db-rotation
.venv/Scripts/python.exe -m scripts.database_transport_runtime once --directory runtime/c02/my-db-rotation
```

`status`의 `observation_only: true`는 조회임을 뜻한다. `phase`, `epoch`,
`recovery_required`, `pending_plan_sha256`, `remaining_history_slots`를 제공하며 저장된 오류는
고정된 공개 분류로만 보여준다. 실행기 생존·현재 서비스 health·마지막 검증의 최신성을 보장하는
신호가 아니다. 실제 검증은 잠금을 확보한 `preflight` 또는 재개 과정의 live 검증이 담당한다.

## 한 번의 인수에서 묶어 확인하는 장애

기존 48개 인수를 유지하면서 첫 교체에 다음 네 종료를 연속으로 주입한다. 공개 checkpoint를
부모 시험기가 확인한 뒤 자기가 생성한 자식만 강제 종료한다. Linux는 SIGKILL, Windows는
가상환경 launcher의 자식까지 포함한 해당 PID 트리 종료를 사용한다. 사용자 Docker 데몬이나
기존 kind를 재시작하지 않는다. 운영 실행기에는 시험용 중단 플래그를 추가하지 않았다.

| 강제 종료 지점 | 디스크에 남아야 하는 단계 | 재개의 의미 |
|---|---|---|
| DB/양 CA 정지와 journal 저장 직후 | `stopped` | 같은 후보·같은 객체를 확인하고 게시 재개 |
| 파일 게시 성공, 다음 journal 저장 직전 | `stopped` | 이미 게시된 후보를 인정하고 멱등 게시 |
| 암호화 구 묶음 정리/commit 성공, journal 저장 직전 | `committing` | 같은 commit을 재확인하고 이력을 한 번만 추가 |
| 원래 leaf pause 복원 성공, journal 저장 직전 | `resuming` | 같은 원래 pause를 복원하고 idle 완료 |

각 지점에서 종료가 실제 비정상 종료인지, 잠금을 다시 얻는지, 후보 지문·고정 컨테이너 ID가
같은지 검사한다. 첫 지점에서는 실행 중 시작·종료·purge·tick/once/run·preflight 거부와
상태 조회 전후 파일 바이트 보존을 함께 확인한다. 이후 두 번째 정상 교체, 구 client 거부,
nonce/폐기 행 지문·업무 CA epoch·leaf 신원 보존과 정상 재시작을 기존 검사로 대조한다.

```powershell
.venv/Scripts/python.exe -m scripts.test_infra_preflight_batch
```

한 고정 소스의 전체 Linux 회귀 → 관측 75개 → 확장된 DB 교체 인수 54개를 순차 수행한다.
실패를 자동 재시도하거나 부분 통과를 전체 성공으로 바꾸지 않는다. 변경 경계의 집중 검사를
먼저 수행하고, 최종 소스 전체 회귀는 로컬 묶음과 정확한 PR head/병합 CI로 구분해 남긴다.

## 범위와 남은 작업

같은 신뢰 호스트·파일시스템의 협조적 관리 도구 사이를 직렬화한다. 다른 directory 사본,
임의 Docker CLI, 악성 관리자, 네트워크 파일시스템의 잠금, 호스트 전원 손실 또는 Docker
데몬 종료까지 방어했다고 주장하지 않는다. 고정 이름의 비밀 helper 중복 차단은 PR41을
유지하며, 이번 네 종료는 helper가 반환한 경계에서 발생한다. 임의 helper 내부 명령 시점의
전원 손실 실험과도 구분한다. 여러 파일의 일괄 원자성·무중단 발급을 제공하지 않는다.

런타임18서비스·10내부망·37볼륨, root/leaf 유효기간과 자동 교체 주기는 그대로다. 새 release
입력으로 새 선택형 환경을 인수하며 이전 descriptor를 새 코드로 자동 재봉인하지 않는다.
앱·탐지·정책·평가 데이터와 동료 저장 계약 코드는 수정하지 않는다. DB/물리 호스트 HA,
백업 통합, 장기 checkpoint, 즉시 세션 폐기와 김택희의 독립 인수는 후속이다.

## 검증 기록

집중 206개가 통과했다. 첫 Windows 시험의 lock 파일 읽기 제한과 가상환경 launcher 자식이
남는 문제를 시험기에 반영한 뒤 다시 확인했다. 운영 잠금의 대기 시간을 늘리거나 거부를
무시하지 않았다. 아래와 원자료에 초기 묶음과 진단 보강 뒤 인수를 구분해 기록한다.
AWS·유료 LLM 호출 없이 로컬 Docker와 기존 공개 저장소의 표준 CI를 사용한다.

첫 고정 소스 묶음은 Linux **2413 통과/기존 경고2**, lock의 Ruff0.17.3, 관측 **75/75** 뒤 기존 CA 두 번째 JWK 교체의 `trust_retired` 경계에서27개 통과 후 중단됐다. 공개 진단만으로 원인을 확정할 수 없었고 소유 자원0을 확인했다. 운영 교체 로직을 수정하거나 실패를54개 성공으로 바꾸지 않았다.

이후 시험기에 고정 오류 분류·저장소 코드 위치만 기록하는 진단을 추가했다. 원문 오류·stdout/stderr·요청·키·지역 변수는 공개하지 않는다. 이 진단과5개 시험만 달라진 최종 소스에서 집중 **211개/신규31개**, 실제 인수 **54/54**를 따로 확인했다. 전체 Linux·관측은 재실행하지 않았다. 최종 전체2418은 정확한 PR head/병합 CI 기록으로 구분한다. 재통과를 초기 미확정 실패의 수정 증거로 확대하지 않는다.

실제 프로세스 종료4회 모두 같은 후보/객체와 잠금 재획득을 확인했고 두 번의 DB 교체·업무 CA epoch3·보안 상태를 보존했다. 소유 컨테이너/볼륨/망0, 기존 kind·ZIP2개·엔진 ID와 앱/동료 계약 코드 보존을 확인했다. [공개 원자료](infrastructure-results/database-transport-process-recovery-20261107.json)에 초기 실패·최종 입력·보고서·최초 공개 anchor·중단 지점별 결과를 기록했다.
