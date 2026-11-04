# 관리 실행 호스트와 전환 기록 이중화

2026-11-04 · I4·I6/C04 후속 · 로컬 Docker 시험 프로필 전용

## 기존 구현에서 발전한 점

[관리 사본 이중화](control-plane-high-availability.md)는 키·상태 저장소 두 묶음을,
[관리 전환 재개](control-transition-recovery.md)는 중단된 전환의 단계를 보존했다. 이전에는 이를 실행하는
Windows 프로세스와 로컬 전환 파일이 살아 있어야 했다. 이번에는 **신뢰된 관리 실행 호스트 두 개와 각각의
전환 기록 저장소**를 두고, 활성 호스트를 제거해도 생존 사본으로 같은 전환을 이어간다.

| 구분 | 구성과 책임 |
|---|---|
| CA 서비스 호스트 a/b | 기존 별도 DinD 데몬·PostgreSQL 동기 복제. 이번 관리 실행 호스트와 다른 계층 |
| 관리 cell a/b | 기존 cell별 9개 볼륨. vault·CA 설정·leaf·갱신·witness·백업·별도 백업 키·reader·control |
| 관리 실행 호스트 a/b | 별도 컨테이너 rootfs, journal·owner 볼륨 각각 2개. 단일 활성, 대기 실행 거부 |
| 공개 전환 기록 | `management-transition.json`의 체크섬·단계·계획·고정 객체 ID를 대기 우선으로 양쪽 저장 |
| 공개 프로필·클러스터 정보 | 양 journal에 보존. Windows 프로필/조정기 캐시 없이 생존 사본과 공개 anchor로 복원 |
| 전환 실행 권한 | 실행 호스트 owner epoch와 관리 cell epoch를 분리. 양 owner의 일치와 현재 활성 site 확인 |

두 실행 호스트가 **같은 부모 Docker와 같은 물리 PC**를 사용한다. 이것은 논리 호스트 제거·독립 볼륨
손실 시험이며, 물리 서버·Docker 데몬·전체 저장장치 장애에 대한 고가용성을 의미하지 않는다.

## 기록과 권한의 보존

`scripts.executor_store`는 전환 기록을 대기 볼륨에 파일 교체/fsync/부모 디렉터리 fsync한 뒤 활성 볼륨에
반영한다. 양쪽 저장을 마친 뒤에만 성공을 반환한다. 대기 저장에 실패하면 활성 기록을 앞당기지 않는다.
대기 기록만 저장된 직후 프로세스가 종료되면 기존 활성은 두 기록의 불일치를 보고 정상 명령을 거부한다.
양 노드 중 높은 숫자를 자동으로 선택하지 않고, 명시적 봉쇄 후 지정한 생존 사본을 사용한다.

복구된 활성과 새 대기는 같은 Linux 논리 경로를 사용하되 서로 다른 볼륨을 가진다. 이 때문에 기존 전환의
대상·이미지·키 후보·동일 전환 ID를 바꾸지 않고 `resume`할 수 있다. 조정기 상태는 기존 관리 cell의
Linux control 사본에서 읽으며 실행 호스트의 조정기 JSON은 캐시다. Root/JWK/백업 키 원문은 공개
journal·프로필·anchor에 넣지 않는다. 체크섬은 손상 검출용이며 악의적인 Docker 관리자를 막는 서명이 아니다.

임시 작업에는 실행 host/site/epoch 표식을 붙이고 양 owner를 읽기 전용으로 전달한다. 실제 명령을
시작하기 직전 `scripts.executor_fence`가 owner를 확인하며, 관리 파일 변경 경로도 같은 검사를 한다.
이전 epoch로 늦게 시작한 임시 작업은 업무 명령을 실행하지 않는다. 기존 leaf·관문은 관리 cell 역할로
보호하고 실행 호스트 전환만으로 무조건 정지하지 않는다. 특히 `opening` 이후의 새 토큰 소비·폐기 기록을
보존하기 위해 copy/초기화/reconcile/writer-stop을 재수행하지 않는다.

## 명시적 호스트 전환 순서

1. 부모 Docker에 프로젝트별 고유 이름의 operator lock 컨테이너를 만들어 여러 콘솔의 동시 전환을 막는다.
2. 지정한 생존 journal/owner의 볼륨 표식, 공개 anchor, 클러스터 정보와 현재 owner를 대조한다.
3. 두 기존 실행기의 고정 ID·이미지·명령·환경·마운트·권한·자원 제한을 검사하고 정지/제거한다.
4. 이전 활성 epoch의 임시 작업을 제거한다. 관리 서비스 안의 실행 중 명령과 남은 작업이 0인지 확인한다.
   공통 Docker 표식이 없는 기존 DinD 호스트도 프로필의 고정 이름·ID·이미지로 직접 확인한다.
   조회 오류나 확인할 수 없는 작업은 성공으로 추정하지 않고 전환을 막는다.
5. 손실된 쪽에 새 세대 journal/owner 볼륨을 만들고 생존 사본을 복제한다. 이전 볼륨은 재사용하지 않는다.
6. 양 owner에 새 실행 epoch·활성을 설치하고 새 활성/대기를 구성한다. 공개 클러스터 정보를 양쪽에 저장한다.
7. 진행 중 관리 전환이 있으면 생존 journal의 같은 전환을 명시적으로 `resume`한다.

이 순서 전체가 분산 트랜잭션인 것은 아니다. operator가 전환 도중 종료되거나 새 볼륨 생성/owner 설치가
부분 실패하면 lock·봉쇄 상태를 남기고 수동 조사가 필요하다. lock 삭제·busy 삭제·큰 epoch 임의 선택을
일반 복구 절차로 제공하지 않는다. 임의 네트워크 분할에서 자동 선출하거나 두 노드로 quorum을 주장하지 않는다.

## 신뢰 경계

두 실행 호스트는 **부모 Docker socket을 가진 신뢰된 유지보수 관리자**다. socket 권한은 사실상 부모
호스트 관리자 권한이며 UID 10001·읽기 전용 rootfs·capability 제거가 이를 비신뢰 실행기로 바꾸지 않는다.
고정 digest의 기존 DinD 이미지에서 Docker CLI만 가져온다. 외부 RPC 서버를 열지 않고 신뢰된 콘솔이
고정 컨테이너 ID로 Docker exec한다. 두 실행기는 network none이며 별도 vault 볼륨을 상시 마운트하지 않는다.

온라인 CA·leaf·관문에 Docker socket이나 offline Root/백업 키를 추가하지 않는다. 실제 키를 읽는 작업은
기존 network-none 일회성 작업으로 유지한다. Docker 관리자 침해, 전체 PC 손실, 앱 SQLite/업무 인증서
볼륨 HA와 전역 antirollback은 이번 범위 밖이다. 탐지·정책·정상/위협 평가 기준과 앱 코드는 바꾸지 않는다.

## 로컬 재현과 운영 명령

```powershell
.venv\Scripts\python.exe -m scripts.test_executor_hosts spec-check --directory runtime/c02/c04/executor-contract
.venv\Scripts\python.exe -m scripts.test_executor_hosts --directory runtime/c02/c04/executor-reproduce
.venv\Scripts\python.exe -m pytest tests/test_executor_hosts.py tests/test_control_transition.py tests/test_control_plane_ha.py -q
```

전체 실행기는 새 CA/키/관리 cell/실행 호스트를 구성하고 종료 시 해당 프로젝트 자원만 정리한다. 완료 뒤
남은 공개 결과 파일은 살아 있는 운영 클러스터가 아니다. 기존 이미지에 모듈만 덧씌우는 이전을 지원하지 않는다.
실제 사용 중인 새 시험 클러스터에서는 공개 descriptor/anchor를 별도로 안전하게 보관한다.

```powershell
# 현재 descriptor로 명시적 호스트 전환. 이전 journal/owner는 격리 보존한다.
.venv\Scripts\python.exe -m scripts.executor_cluster takeover --descriptor runtime/c02/<project>-console/cluster.json --site b
# 콘솔 캐시가 없어도 공개 anchor + 명시한 생존 볼륨으로 복원하고 전환한다.
.venv\Scripts\python.exe -m scripts.executor_cluster recover --anchor runtime/c02/<project>-console/anchor.json --site b --journal <project>-executor-b-g1-journal --owner <project>-executor-b-g1-owner --descriptor runtime/c02/<project>-console/cluster.json
# 복원한 활성 호스트에서 동일한 관리 전환의 단계 확인과 재개
.venv\Scripts\python.exe -m scripts.executor_cluster journal --descriptor runtime/c02/<project>-console/cluster.json
.venv\Scripts\python.exe -m scripts.executor_cluster resume --descriptor runtime/c02/<project>-console/cluster.json
```

CLI는 명시된 대상과 고정 소유 객체만 다룬다. `recover`가 성공한 뒤 정상 관리를 시작하기 전 pending
관리 전환을 확인하고 이어간다. 전환 파일이나 이전 세대 볼륨을 임의 삭제해 차단을 해제하지 않는다.

## 검증 결과와 후속

신규 단위 사례는 68개다. Windows 전체는 **1,087 통과·1 건너뜀**, Linux Docker 전체는 **1,088 통과**다.
Windows에서 별도 OS 권한이 필요한 peer symlink 검사를 Linux에서 실행했다. Ruff도 통과했다.
기존 의존성 경고는 Windows 3개·Linux 2개이며 이번 작업에서 해당 의존성이나 탐지 기준을 바꾸지 않았다.
최종 새 CA 클러스터 1회에서 **실행 호스트 검사 15개·기존 관리 저장소 제거 확인 2개**를 통과했다.
별도 공개 메타데이터 사전 실험은 **8개**다. 기존 35개/프로세스 종료 9회 캠페인을 이번에 재실행한 것으로
더하지 않는다. 최종 전체 흐름은 준비부터 검증 종료까지 912.006초였으며 전환별 RTO/RPO·성능 비교 수치는 아니다.

| 이번에 실제로 확인한 조건 | 결과 |
|---|---|
| 첫 전환 `roles` 기록의 대기 저장 직후 프로세스 종료 | 실제 exit 73. 옛 활성의 journal 불일치 거부. 실행 호스트 a와 그 journal/owner 제거 후 b 사본으로 같은 전환 ID·키 후보 재개 |
| Windows 공개 캐시 유실 | 프로필/조정기 캐시 없이 공개 anchor와 명시한 생존 볼륨에서 클러스터 복원 |
| Root·issuer·JWK 교체 | 생존 실행기에서 epoch 1 완료. 66개 이전 JWK × CA 2대의 신선한 요청 132건 거부, 현재 mTLS 갱신 성공 |
| 두 번째 전환 `opening` 이후 프로세스 종료 | 실제 exit 73. 실행 호스트 b와 journal/owner 제거 후 a 사본으로 복원. 재개 전 새 JWT를 발급·소비하고 재개 뒤 재사용 거부 확인 |
| 같은 전환의 재실행 | 두 전환 모두 같은 receipt·전환 ID·관리 epoch 반환. 최종 관리/실행 epoch 각각 3, 활성 a, 양 저장소 세대 2 |
| 보안 상태의 만료 여부 | 소비된 기준 토큰 약 782.925초·폐기된 인증서 약 1,083.925초가 남은 상태에서 각각 재사용·갱신 거부. 새 nonce는 성공 |
| 백업·키·checkpoint | 생존 사본의 암호화 백업과 별도 키를 최신 보안 checkpoint와 대조해 인증. 이 실행은 CA DB 전체 cold restore 재실행이 아님 |
| 봉쇄·저장소 제거 | 실행 호스트 전환 2회, 옛 실행 저장소 4개·옛 관리 cell 볼륨 18개 삭제. 전환 전 실행 중 명령/임시 작업 0, 고정 서비스 ID 각각 2개·6개 확인 |
| 사전 거부 시험 | 대기 실행 거부, 대기 기록만 저장한 실제 종료/불일치 거부, 표식 없는 고정 서비스의 실제 실행 중 명령 때문에 전환 거부, 옛 임시 작업 제거, 옛 epoch 명령 시작 차단 |

CA 재기동 전에 만든 JWT는 step-ca의 부팅 시각 검사로 거부될 수 있다. CSR만 leaf 정지 전에 준비하고,
접속 재개 후 읽기 전용 vault/network-none 시험 작업에서 새 JWT를 만든다. 이 검사를 끄거나 인증 시간을 늘리지 않는다.

[공개 결과·109개 입력 지문·이미지 지문·정리 원자료](infrastructure-results/c04-executor-hosts-windows-20261104.json)를
보존한다. 두 이미지 안의 앱/스크립트 등 **89개 파일 각각**을 원본과 대조했다. 이미지에 복사하지 않고
실행기가 제공하는 설정/시험 입력 **20개**는 따로 표시한다. 새 단위 테스트 파일 지문도 보존하며 Git의
LF 정규화 지문과 Windows에서 실제 읽은 원본 지문을 구분한다.

초기 사전 실험은 BuildKit의 `FROM sha256:<ID>` 해석 때문에 실패했다. 빌드 참조만 해당 프로젝트의
로컬 태그로 바꾸고 실행 ID 고정은 유지했다. 첫 CA 준비 실행은 공통 표식이 없는 DinD의 실행 중 명령도
직접 검사해야 함을 점검 중 발견해 중단했다. 고정 이름/ID/이미지 검사와 실제 거부 시험을 추가한 뒤 새
클러스터로 최종 실행했다. 이 준비 실행과 이전의 더 좁은 사전 실험은 최종 성공 합계에서 제외한다.

최종/예비/단위 시험 **7개 프로젝트 범위**를 실행기 밖에서 다시 조회해 컨테이너·볼륨·네트워크·이미지
태그 잔여 0을 확인했다. 기존 forensics 컨테이너의 고정 ID/실행 상태와 사용자 ZIP 두 개의 지문은 보존됐다.
AWS·유료 LLM·실계정 변경·호스트 OS 신뢰 저장소 변경은 수행하지 않았다.

같은 PC 시험을 물리 HA·무중단 SLA·제품 선정 우열·팀원 독립 검토·전체 주간 계획 완료로 확대하지 않는다.
실제 물리 분리에는 독립 실행 호스트/저장소/네트워크, 외부 봉쇄 수단과 다수결 저장소, 운영자 전환 자체의
중단 복구, 접근 감사와 비밀 관리 경계를 별도로 설계하고 장애 행렬로 재검증해야 한다.
