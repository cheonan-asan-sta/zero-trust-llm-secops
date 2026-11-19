# 고정한 감사 witness의 주기 수집과 중단 복구

2026-11-20 · `extra` · 구현 `e6c9b12`. [08:00까지의 지속 목표](extra-until-0800-20261120.md)는 진행 중이다. 별도 로컬 확인 기록에 작업을 먼저 저장하고, 서명 영수증이 실제 저장된 것을 검증한 뒤 확인 기록을 전진시키는 수집기를 추가했다. 같은 호스트의 실험이며 실제 독립 보관·SSO·운영 배포 인수는 아니다.

## 구현한 흐름

1. 관리자가 witness 공개키·현재 영수증을 외부에서 고정해 새 확인 디렉터리를 초기화한다. 프로필에는 원본 감사 DB 위치, stream, 공개키, 초기 영수증, 수집/만료/용량 정책이 들어간다. 프로필 SHA256도 별도로 보관한다. 최신 영수증을 검색해 자동 채택하지 않는다.
2. `lease.sqlite3`의 실제 SQLite 잠금으로 한 수집 작업만 허용한다. `observer.sqlite3`에는 작업 ID·이전 영수증·시작 시각을 먼저 커밋한다. 잠금 DB를 분리했으므로 이 pending 커밋이 서명 전에 완료된다. 종료된 프로세스의 PID나 잠금 파일 존재를 신뢰하지 않는다.
3. witness에 같은 작업 ID로 관측을 요청한다. 응답 서명/범위/이전 기준/시각을 확인하고 witness journal에도 그 영수증이 실제 현재 head로 저장됐는지 확인한다. 원본 감사 DB의 이전 최소 이력과 반환된 관측 head도 같은 읽기 snapshot에서 검증한다.
4. 확인 영수증 추가와 pending 삭제를 한 트랜잭션으로 커밋한다. 응답을 잃으면 원래 pending ID로만 재개한다. 서명 이후 중단은 기존 서명·시각·digest를 그대로 재사용하며 신선도를 갱신하지 않는다. 다른 writer가 전진했거나 원본/확인 기록이 외부 최소 기준보다 과거라면 거부한다.

수집기 디렉터리와 witness/원본 DB는 경로가 분리돼야 한다. 공개키만 복사하며 개인키는 복사하지 않는다. POSIX는 디렉터리0700/파일0600을 사용하지만 동일 관리자 권한의 공격자나 Windows ACL 인수를 증명하지 않는다. pending checksum은 손상 검사용이며 사람의 인증 서명이 아니다. 외부 프로필/영수증 pin 보호가 필요하다.

```powershell
python -m scripts.audit_witness_observer init --directory <새-확인-디렉터리> --witness-directory <witness> --database <audit.sqlite3> --public-key-sha256 <공개키-pin> --expected-receipt <관리자가-확인한-현재-영수증>
python -m scripts.audit_witness_observer cycle --directory <확인-디렉터리> --profile-sha256 <프로필-pin> --minimum-receipt <외부에-보관한-최소-영수증>
python -m scripts.audit_witness_observer watch --directory <확인-디렉터리> --profile-sha256 <프로필-pin> --minimum-receipt <외부-최소-영수증> --cycles 2
python -m scripts.audit_witness_observer status --directory <확인-디렉터리> --profile-sha256 <프로필-pin> --minimum-receipt <외부-최소-영수증>
```

기본 수집60초·만료180초. `watch`는 운영자가 실행하는 명령이며 서비스 설치/자동 시작은 하지 않았다. `--cycles`가 없으면 명시적 중지까지 실행한다. 이번 실제 명령 시험은 1초 간격 두 회로 제한했다. 지속 실행 중 오류가 나도 pending/pin을 초기화하지 않으며 제한 실행 중 실패가 있었다면 종료 코드는1이다. 현재 일반 오류 표시는 `unavailable`이며 다음 보강에서 원인별 경보를 연결한다.

## 상태 해석

서명된 관측 시각으로 stale/clock regression을 판단한다. 원본에 관측 이후 행이 있으면 unobserved, 미확인 작업은 pending, 타 writer 전진은 witness_advanced, 저장 한계는 capacity_pressure/exhausted다. 과거 관측의 재개를 새로운 관측으로 세지 않는다. `--offline`은 저장된 서명만 확인하며 healthy가 될 수 없다. healthy도 수집된 snapshot의 신선도/일관성이지 원천 이벤트 생산기의 생존이나 다음 서명 가능성을 보증하지 않는다. `signing_capability_checked=false`, `independent_storage_verified=false`, `automatic_activation_allowed=false`를 유지한다.

## 무료 로컬 검증과 제한

관련 묶음은 **Windows102통과·2제외, Linux104통과·제외0**. 새 수집기22건은 양쪽 통과다. 서명 전·서명 저장 후·확인 커밋 후에 별도 실제 프로세스를 종료 코드71/72/73으로 중단한 뒤 새 CLI 프로세스로 확인했다. 새 서명 중복0, 원본 감사 행 변경0, pending 복구/삭제와 기존 영수증 보존을 확인했다. 확인 후 종료 시험은 처음에 시험 주입 함수를 잘못 연결해 실패했으며 연결을 수정한 뒤 실제 종료 코드73을 검증했다. 최초 실패 원본도 보존했다.

서명됐지만 witness journal 커밋이 사라진 경우, 감사 rollback, 타 writer, 확인 기록 rollback, 잘못된 프로필/외부 pin, pending 손상, 동시 실행, clock regression, 신선도/미수집/용량, offline, 정책 입력을 거부하는 경계를 확인했다. raw 결과와 구현 지문은 [manifest](infrastructure-results/extra-witness-observer-20261120.json)에 있다. 전체 프로젝트 회귀를 새로 실행한 수치로 합산하지 않는다.

무료 동결 재생은 이전 보고서와 **모든 행/분류/지표가 동일**했다. 기존360건의 실제 LLM 결과 F1 93.41%·재현율90.56%, 기존 rule/hybrid F1 78.26%/78.09%이며 탐지 목표는 미달이다. 새 API 호출/모델 변경은 없다. 기능22건을 독립 성능 평가에 합산하지 않는다. 백업/복원·경보 흐름 연결 및 실제 독립 운영 인수는 남았다. 유료/API/AWS/Docker/push/CI/병합0.
