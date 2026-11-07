# CA DB 복원과 최신 보안 체크포인트 대조 — 구현 초안

2026-11-08 · 채희주 인프라 범위. **Docker 통합 인수 미실행, 병합 전 초안**.

이전 PR43은 암호화된 백업을 격리 PostgreSQL에서 복원하고 백업 당시의 보안 데이터를
대조한다. 이번 초안은 별도 체크포인트와 비교해 과거 백업이 마지막으로 기록한 폐기·토큰 소비·
발급 상태를 되돌릴 가능성이 있으면 거부하는 검사를 추가한다.

## 구현

- `database_recovery_runtime` 선택 프로필은18서비스·10내부망·41볼륨이다. 기존39볼륨
  백업 프로필에 체크포인트와 독립 키 볼륨2개를 더한다. 온라인 서비스는 두 볼륨을 연결하지 않는다.
- 기존 백업 작업의 관리 잠금을 유지하고 leaf pause·고정 CA2개 정지·DB 세션0·보안 테이블
  지문 대조를 마친 `stopped` 단계에서 체크포인트를 게시한다. 체크포인트 오류 시 발급을 재개하지 않는다.
- AES-256-GCM으로 프로젝트·목적·순번·이전 지문·백업 manifest를 인증한다. 호스트 descriptor의
  순번/지문과 다른 볼륨 기록은 거부한다. 게시 직후 호스트 저장 전에 중단되면 정확히 같은 다음
  기록만 채택한다. 정상 재시작으로 순번을 초기화하지 않는다.
- `assess`는 암호화 백업의 manifest를 인증하고 마지막 체크포인트의 보안5테이블 행수·지문이
  전부 같은 경우에만 격리 복원을 실행한다. 행을 합치거나 SQL을 운영 DB에 적용하지 않는다.
- 도우미는 network none·비root·읽기 전용 rootfs·capability 제거·로그 저장 비활성화·메모리와
  swap 합계128MiB 제한으로 실행한다. 키는 읽기 전용이며 복원 PostgreSQL에 전달하지 않는다.

## 최신성의 범위와 신뢰 경계

**최신은 마지막 명시적 정지 체크포인트 시점**이다. 백업 이후 발생한 모든 회수를 자동으로
수집하는 외부 witness나 실시간 권한 회수 원장이 아니다. 체크포인트 이후 변경은 다음 명시적
백업/체크포인트까지 포함되지 않는다. 따라서 `checkpoint_compatible=true`는 운영 복원 허가나
현재 시점의 접속 허가가 아니다. 결과에도 `live_restore_authorized=false`를 반환한다.

같은 호스트의 관리자와 descriptor는 신뢰한다. 키·호스트 anchor·체크포인트를 함께 되돌리는
관리자 공격, 호스트 전체 소실, 독립 원격 저장소, 외부 단조 카운터까지 방어했다고 주장하지 않는다.
정상 발급 증가만 있어도 지문이 달라지면 거부하는 보수적 검사이며, 과거 백업을 최신으로 만드는
안전한 병합·운영 복구 절차는 후속이다.

## 실행 준비

```powershell
.venv/Scripts/python.exe -m scripts.database_recovery_runtime up --directory runtime/c02/my-recovery
.venv/Scripts/python.exe -m scripts.database_recovery_runtime backup --directory runtime/c02/my-recovery
# manifest.json: 해당 백업 journal의 manifest 객체만 담은 공개 JSON
.venv/Scripts/python.exe -m scripts.database_recovery_runtime assess --directory runtime/c02/my-recovery --manifest manifest.json
.venv/Scripts/python.exe -m scripts.database_recovery_runtime down --purge --directory runtime/c02/my-recovery
```

위 명령 경로는 구현됐으나 아직 실제 Docker 인수로 검증하지 않았다. 새 directory에서 시험한다.
기존 프로필을 자동 변환하거나 기존 데이터를 재기준화하지 않는다.

## 확인한 결과와 남은 검증

집중 pytest **100개 통과**(새 체크포인트23개, 기존 백업·관리 잠금77개), 변경 파일 Ruff 및
`git diff --check` 통과. 첫 실행은 도구 호출이 장시간 반환되지 않았고 기존 관리 잠금 시험의
`taskkill`10초 timeout으로 **99통과/1실패**였다. 같은 소스 재실행은4.35초에100통과했다.
원인은 호스트 실행 지연과 연관됐을 가능성이 있으나 확정하지 않는다. 통합 성공으로 대체하지 않는다.

최종 로그를 저장한 집중 재실행은100통과/3.20초이며, 추가 release·CI 구성·DB 사전 점검
회귀는62통과/1skip/4.42초였다. 이 결과도 새 Docker 복원 인수를 대신하지 않는다.
[초안 검증 기록](infrastructure-results/database-recovery-checkpoint-draft-20261108.json)에 소스 지문과
미실행 검사를 명시한다.

다음 드라이버를 추가했지만 **아직 실행하지 않았다**:

```powershell
.venv/Scripts/python.exe -m scripts.test_database_recovery_runtime --directory runtime/c02/recovery-acceptance
```

기존 백업 집중13개 뒤 실제 CA API의 추가 발급·폐기, 새 체크포인트 게시, 과거 백업 거부,
최신 백업 격리 복원, 재시작 후 anchor 보존을 검사하도록 구성했다. 실행 결과에 따라 보완해야 한다.
Docker 통합·전체 Linux 회귀·정확한 PR head CI·병합 후 CI가 남아 있다. 기존 PR43의2477/67
결과는 이번 새 소스의 결과가 아니다. 새 인수를 CI 필수 작업에 연결하는 일도 검증 후 수행한다.

오전7시 마감 전에 새 장시간 인수는 시작하지 않고 이 상태를 초안으로 보존한다. AWS와 유료
LLM은 호출하지 않았다. 이번 작업으로 새 Docker 시험 자원을 만들지 않았다.
