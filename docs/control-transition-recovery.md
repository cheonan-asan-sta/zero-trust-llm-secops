# 관리 전환 중 조정기 종료와 안전한 재개

2026-11-04 · 기존 로컬 관리 이중화의 후속 · 새 코드가 포함된 시험 이미지/관리 프로필 대상

후속 [관리 실행 호스트·기록 이중화](executor-host-high-availability.md)는 아래 단일 실행 호스트/journal
생존 조건을 별도 시험 프로필에서 보완한다. 두 실행기·별도 journal·명시적 봉쇄 후 생존 사본 재개를 사용한다.
아래 기존 검증 수치/단일 호스트 설명은 당시 결과이며 물리 PC/Docker 전체 HA 조건은 여전히 남는다.

## 이전 구현에서 보완한 점

[관리 이중화](control-plane-high-availability.md)는 관리 사본을 명시적으로 바꾸지만 전환 도중 호스트
조정기 프로세스가 종료되면 부분 구성 상태를 자동으로 해석하지 않았다. 이번에는 **공개 전환 journal**에
대상·단계·이미지·컨테이너 ID·복제 저장소와 키 계획을 기록하고, 별도의 `resume` 명령으로 이어간다.
일반 관리 명령은 미완료 journal을 발견하면 거부한다. 탐지·정책·개선 전 평가 결과와 앱 코드는 변경하지 않는다.

호스트 실행기와 그 로컬 디스크가 살아 있어야 한다. journal은 같은 신뢰된 호스트의
`control_directory/management-transition.json`이며 root/JWK/백업 키 원문을 담지 않는다. 파일 교체 전
fsync와 가능한 플랫폼의 부모 디렉터리 fsync를 사용한다. 이번 검증은 **프로세스의 강제 종료**다.
호스트/디스크/전원 전체 손실, Windows 디렉터리 fsync 또는 분산 quorum 보장을 뜻하지 않는다.

## 전환 단계

| durable 단계 | 그 단계에서 이어가는 작업 |
|---|---|
| `prepared` | 전환 의도를 먼저 기록. 이전 관리자의 고정 ID를 정지/제거하고 CA writer 정지·DB 세션 0·동일 primary system ID를 재확인 |
| `fenced` | 후보의 공개 계획/키 일치·tree digest와 조정기 상태를 기록. 계획된 새 볼륨만 생성하고 소유 표식을 확인 |
| `copied` | 복제 파일의 동일한 부분 사본만 이어가기. 원본 digest 변경·다른 내용·예상 밖 파일은 거부 |
| `roles` | 동일한 새 관리 epoch/역할을 양 사본에 설치. 양 관문과 CA writer가 닫힌 장벽에서만 witness를 대조하고 leaf pause 설정 |
| `reconciled` | CA의 TLS 상태를 확인하고 계획된 leaf·읽기 전용 대기·두 관문을 구성. 이때 관문은 닫힌 상태 |
| `services` | 컨테이너 ID·전체 프로필을 확정. Linux control 두 사본과 Windows 공개 캐시에 같은 프로필 저장 |
| `published` | 역할·서비스·소유 ID를 확인한 뒤 `opening` 의도를 먼저 영속화 |
| `opening` | 이미 열린 관문은 다시 초기화하지 않음. 닫혀 있으면 기존 unfreeze만 수행. 이후 journal을 완료로 확정 |
| `complete` | 같은 결과를 반환하고 소유 ID를 확인. 두 번째 볼륨 생성·키 후보 재생성·CA POST 재전송 없음 |

후보 전환 가능 단계는 기존처럼 authority `idle`/`prepared`뿐이다. 기존 busy/leaf 게시 중단의
의미를 추정해 지우지 않는다. 이 기능은 전환 자체의 과정을 이어가며 임의의 키 교체 중간 단계나
불확실한 발급 요청을 성공으로 간주하는 기능이 아니다.

## 불확실한 Docker 응답과 중복 생성 방지

전환 ID와 객체 생성 사양을 journal에 먼저 저장하고 Docker 객체에도 표식을 붙인다. 생성 후 ID를
기록하기 전에 프로세스가 종료되면, 재개 시 이름만 보고 재사용하지 않는다. 이미지·전환/사양 표식·
명령·환경변수·UID·읽기 전용 rootfs·capability·네트워크·마운트·자원 제한을 검사하고 같은 객체의 ID를
기록한다. ID를 이미 기록한 뒤 객체가 바뀌거나 없어졌으면 다른 객체를 새로 만들어 대신하지 않는다.
볼륨도 계획한 이름과 전환 소유 표식이 일치해야 한다. 알 수 없는 관리 RW 작업은 계속 전환을 막는다.

journal의 checksum은 우발적 변경/잘림을 검출한다. 이를 악의적인 Docker/호스트 관리자를 막는 서명,
외부 신뢰 앵커나 전역 antirollback으로 표현하지 않는다. journal과 Docker 권한은 기존 신뢰 경계 안에 있다.
이전 관리 컨테이너를 찾지 못하면 같은 고정 ID가 다른 이름으로 존재하지 않는지도 확인한다. Docker
조회 오류를 객체 부재로 취급하지 않는다.

접속을 연 뒤 재시작하면 가장 중요한 것은 **새로 소비한 토큰/폐기 상태를 되돌리지 않는 것**이다.
`opening` 이후 재개는 seed·역할 초기화·witness reconcile·writer-stop을 다시 수행하지 않는다.
살아 있는 최신 보안 journal을 읽어 열린 상태를 확인하고 완료 기록만 확정한다. 요청 성공/응답이 불명확한
업무 POST를 다시 전송하는 일반 재시도 장치는 추가하지 않았다.

## 로컬 실행과 운영 절차

```powershell
.venv\Scripts\python.exe -m scripts.test_control_transition spec-check --directory runtime/c02/c04/transition-contract
.venv\Scripts\python.exe -m scripts.test_control_transition --directory runtime/c02/c04/transition-reproduce
.venv\Scripts\python.exe -m pytest tests/test_control_transition.py tests/test_control_plane_ha.py -q
```

실행 중인 새 시험 프로필에서 전환을 시작/재개하는 명령은 다음과 같다. 완료 후 자동 정리된 프로필이나
구 코드가 들어 있는 이전 이미지의 인플레이스 마이그레이션은 이번 범위가 아니다. 새 실행기는 고정 도구를
재사용하되 현재 소스를 포함하는 이미지를 만든다.

```powershell
.venv\Scripts\python.exe -m scripts.control_plane_ha promote --profile <실행중인-profile.json> --target b --primary a
.venv\Scripts\python.exe -m scripts.control_plane_ha resume --profile <같은-profile.json>
```

`resume`은 새로운 대상/epoch를 선택하지 않고 journal에 기록한 이전을 이어간다. journal이 손상되거나
필요한 객체가 바뀌면 정지한 상태를 보존한다. busy/전환 파일을 삭제하거나 profile의 이미지/ID를 임의로
바꾸어 우회하지 않는다. 접속 재개 이후의 재시작에서도 새 요청을 되돌리지 않도록 단계가 분리돼 있다.

통합 실행기는 실제 호스트 조정기 프로세스를 지정 지점에서 `os._exit(73)`으로 종료한다. 다음 실행은
별도 프로세스이며 OS 파일 lease를 새로 얻는다. 예외를 잡고 같은 객체에서 계속하는 시험과 구분한다.
실행 중 journal 변조 거부, 생성 직후 ID 미기록 객체의 같은 ID 재사용, 완료 후 같은 명령 재실행,
접속 재개 뒤 완료 기록 전의 실제 토큰 소비와 재개 후 재사용 거부를 함께 대조한다.

AWS·유료 모델·실계정·OS 신뢰 저장소 변경은 필요 없다. `runtime` 비공개 로그/키/시험 토큰은 업로드하지
않고 공개 요약만 별도로 저장한다. 시험 자원만 정리하며 기존 Docker 작업과 사용자 압축본은 보존한다.

## 검증 기록과 한계

최종 새 클러스터 **1회·총 35개 검사**를 통과했다. 같은 실행에서 기존 관리 이중화 20개를
재검증하고 중단/재개 검사 15개를 추가했다. 이전 PR의 20개나 예비 실행 결과와 합산하지 않는다.
호스트 조정기 강제 종료는 첫 전환 8회·두 번째 전환 1회로 총 **9회**다. 활성 신원 3개·등록 JWK
66개, 관리 epoch 1→2→3과 authority epoch 1을 사용했다.

| 실제 검사 | 결과 |
|---|---|
| 첫 전환의 8개 중단 지점 | fence·볼륨 생성·복제·역할 설치·컨테이너 생성·서비스 구성·공개 프로필 저장·접속 재개 이후 각각 새 프로세스로 재개 |
| 미완료 관리 명령·변조 | 각 중단 뒤 일반 control 접근 거부, checksum이 맞지 않는 journal의 재개 거부 |
| 생성 후 ID 기록 전 종료 | 이미지·사양·소유 표식을 검증하고 같은 컨테이너 ID 채택, 중복 생성 없음 |
| 완료 명령 재실행 | 두 전환 각각 같은 receipt·관리 epoch 반환 |
| 키 교체 연속성 | 동일 준비 키 계획을 root/issuer/JWK epoch 1로 완료, 양 CA의 이전 JWK 새 요청 132개 거부 |
| 접속 재개 후 중단 | CA 재기동 뒤 새 JWT를 만들어 실제 발급 성공. 완료 기록 확정 후 같은 JWT의 재사용 거부 |
| 이전 보안 상태·백업 | 미만료 소비/폐기 거부·새 nonce 정상·cache 유실 뒤 현재 보안 상태와 백업 인증, 이전 볼륨 18개 실제 삭제 |

첫 전환 호출부터 반환까지 220.563초를 관측했다. 의도적인 종료 8회와 별도 프로세스 시작/검사까지
포함한 한 표본이므로 기존 정상 전환 66.500초와의 동등 조건 성능 비교나 운영 RTO가 아니다.
최종 authority 단일 호출의 최대 관측값은 33.343초다. 시험 상한 180초와 관측값을 구분하고,
예비 60초 시간 초과도 별도 기록한다. 서비스 인증·TLS·토큰 만료 조건을 바꿔서 얻은 수치가 아니다.
보안 거부 대조 시작 때 기존 소비 토큰 약 759.498초, 폐기 인증서 약 1059.498초가 남아 있었다.
접속 재개 후 새 토큰은 CA 재기동 이후 정상 발급한 동일 요청으로 재사용 거부를 확인한다.

[공개 결과·소스/이미지 지문·예비 실패·정리 원자료](infrastructure-results/c04-control-transition-windows-20261104.json)를
별도로 보존한다. 신규 단위 사례는 58개다. 전체 Windows/Linux 회귀 결과는 다음과 같다.

| 전체 회귀 검사 | 결과 |
|---|---|
| Windows pytest | 1019 통과·1 건너뜀, 기존 의존성 경고 3개, 109.87초 |
| Linux Docker Ruff/pytest | Ruff 통과, 1020 통과·건너뜀 없음, 기존 의존성 경고 2개, 77.31초 |

최종 실행과 준비/실패 실행 총 5개 프로젝트의 전용 container·volume·network·image tag를 같은 작업자의
별도 Docker 조회로 확인해 잔여 0개였다. 전체 회귀용 이미지 태그도 제거했다. 기존
`pod-forensics-20261025-control-plane`은 같은 ID로 실행 중이고 사용자 `docs.zip`/`docs/week03.zip`은
해시가 같으며 Git에 추가하지 않았다. Windows에서 건너뛴 symlink 사례는 Linux에서 실행했다.
전체 테스트 시간·단계 시간은 한 실행의 관측값이며 업무 요청 지연/운영 SLA 수치가 아니다.

사전 점검에서 시험 실행기의 import 누락을 발견해 서비스 생성 전 준비를 중단/정리한 실행은 제외한다.
첫 통합 예비 실행은 중단/재개 11개 검사를 통과했지만 뒤이은 authority `quiescing_retirement` 단계에서
기존 실행기의 60초 대기 상한을 넘겨 `TimeoutExpired`로 종료됐다. 해당 실행은 완료 합계에서 제외하고
자원을 정리했다. 새 프로필의 시험용 단일 authority 단계 상한을 180초로 정하고 단계별 시간을 기록한다.
기존 서비스 TLS/인증·발급/폐기/만료 판정이나 앱 worker의 20초 process-death 제한은 바꾸지 않았다.
그다음 실행은 키 교체까지 통과했으나 두 번째 전환 전에 이미 정지한 발행기에서 시험용 요청을 만들려
해 실패했다. 시험 요청을 발행기 정지 전에 준비하도록 순서를 고치고 관련 회귀 사례 2개를 추가했다.
이 실행도 전체 성공 합계에서 제외한다. 검증 대상 운영 전환 코드는 이 예비 실패 중 변경하지 않았다.
다음 실행은 재기동 전 발급한 시험 JWT를 새 CA가 401로 거부했다. CA 로그의 `token issued before the
bootstrap of certificate authority`를 확인했다. 이 보호를 유지하며 정지 전에는 CSR만 보관하고,
접속 재개 뒤 네트워크 없는 읽기 전용 보관함 작업에서 현재 JWK로 새 JWT를 만든다. 이 작업은 시험
자격 준비 전용이며 일반 관리 명령의 pending 차단을 해제하거나 온라인 제어기에 vault를 주지 않는다.
관련 회귀 검사를 추가하고 해당 실패도 최종 합계에서 제외한다.

- 같은 부모 Docker/PC와 생존한 신뢰된 실행기·로컬 journal을 사용한다. 물리 관리 호스트/데몬 분리,
  journal 디스크 손실, 자동 선출·consensus·지역 장애 복구는 후속이다.
- 허용된 체크포인트와 기록된 전환만 재개한다. 임의의 authority 중간 단계·불확실한 원격 POST는 거부한다.
  live Docker API 요청을 강제로 끊은 모든 타이밍·파일시스템 전원 손실의 전수 검증으로 확대하지 않는다.
- 업무 앱 SQLite/세션·공유 업무 인증서 저장소 HA, CA DB 복구와 관리 전환의 전체 복합 장애 행렬,
  운영 부하/SLA/RPO/RTO와 팀원 독립 재현은 아직 별도다.
