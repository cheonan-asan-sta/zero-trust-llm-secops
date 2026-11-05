# 3주차 I4: 앱 보안 상태 백업·복구

2026-11-05 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.
대상 계획은 **11/16~11/22의 3주차**이며 해당 작업을 미리 진행했다.
김택희의 앱 의미·독립 재현 검토와 3주차 전체 완료는 별도다.

## 체크포인트 저장 실패 후 재사용 차단 보강

초기 구현 [PR #30](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/pull/30)의 최종 CI는
전체 회귀·복구 15개·mTLS 41개·이미지 빌드를 통과했다. 추가 검토에서 새 checkpoint 파일 저장이
실패하면 예전 checkpoint/anchor가 서로 일치해 과거 백업이 다시 사용될 수 있는 경로를 발견했다.
새 세션의 일괄 회수만으로 최신 inbox/소비 이력의 유실까지 해결할 수 없어 후속으로 차단했다.

이제 **복사/검증 전에 다음 세대의 차단 pin을 먼저 저장**하고, 백업/복원은 public 세대와
완료된 anchor 세대가 같을 때만 허용한다. 스냅샷·checkpoint·anchor 쓰기가 중단되면 과거 사본을
사용할 수 없다. 현재 정지 원본을 다시 검증해 새 checkpoint를 정상 발행한 뒤에만 재개한다.
차단 기록 자체를 저장할 수 없는 경우도 운영자는 작업을 중단하고 노출을 재개하지 않아야 한다.
신뢰 호스트와 정지 경계·전체 제어 저장소 rollback 제외 조건은 그대로다.

[보강된 로컬 원자료](infrastructure-results/app-state-recovery-checkpoint-20261105.json):
복구 단위 **51개/83.10초**, 실제 Docker **18/18** 통과, 소유 컨테이너/볼륨 **0/0**.
49,152-byte DB/18 journal records에서 backup 2.9436초, restore job 2.5752초,
DB 유실→HTTP 준비 11.7072초이며 정지 증거 경계의 journal 손실은 0이다.
원본 DB/기동/권한 거부 등 초기 검사를 모두 반복하고 실제 checkpoint 저장 실패와 구 사본 거부를 추가했다.
아래 초기 15개·전체 회귀 1,940개 기록은 그 당시 근거로 보존한다. 최신 전체 회귀 결과는 후속 PR의
정확한 head 및 최종 병합 commit CI 기록을 따른다. PR #30의 병합 후 CI는 이 보강을 위한
후속 검증으로 대체하려고 취소했으며, 취소를 성공으로 기록하지 않는다.

## 해결한 공백

기존 CA DB/호스트 복구와 런타임 업그레이드 DB 호환 시험은 앱의 권한 상태를
안전하게 되돌리는 절차를 보장하지 않았다. 오래된 DB를 그대로 시작하면 이미 소비한
접속권한·회수·폐기한 신호 키 정보를 잊을 수 있다.

이번에는 기존 `ZeroTrustOperations.revoke`와 journal/inbox 무결성 검증을 재사용하는
별도 로컬 관리 경로를 추가한다. 앱·정책·인가 API·탐지기·평가 데이터/임계값은 변경하지 않는다.
복원 전 세션의 기존 허용을 전부 무효화하고 검증에 성공해야 앱을 시작한다.

## 적용 범위와 신뢰 조건

| 구분 | 이번 범위 |
|---|---|
| 보존 | SQLite v2 정책 journal의 활성·압축 보관 이력, 공유 signal inbox 전체 테이블, 공개 신호원 registry |
| 추가 봉쇄 | 모든 테넌트의 복원 전 세션을 기존 회수 함수로 회수. 공개 목록 API의 100개 제한을 사용하지 않음 |
| 백업 | SQLite `Connection.backup`, 별도 키 AES-GCM 암호화, 목적·source·세대·내용 지문 인증 |
| 최신 증거 | 백업과 분리한 관리 볼륨의 checkpoint/anchor. 새 checkpoint는 이전 admission을 먼저 차단 |
| 복구 승인 | 새 격리 디렉터리에 복원·검증·회수 후 Ed25519 서명. 별도 public 볼륨의 현재 pin과 일치해야 기동 |
| 일반 앱 권한 | 복원 데이터와 읽기 전용 public 신뢰만 연결. backup/checkpoint/서명 개인키·백업 볼륨 연결 안 함 |
| 제외 | 사건/감사/outbox JSONL 전체 복원, 온라인 자동 백업, 상시 외부 보안 witness, 원격/물리 HA, 운영 배포 |

**계획 정비용 실험이다. 모든 쓰기 프로세스를 정지·봉쇄한 뒤 최신 checkpoint를 만들고,
그 경계를 유지한 채 백업/복원해야 한다.** 실행기는 자신이 만든 모든 writer의 고정 ID·소유
label·볼륨·정지 상태를 Docker에서 검사한다. 임의 호스트/외부 writer 발견 기능은 아니다.
`Store`/저수준 CLI만 호출해서 실행 중인 앱을 안전하게 백업한다고 해석하면 안 된다.

checkpoint 이후 원본이 바뀌면 새 백업을 거부하고, 새로운 checkpoint가 생기면 과거 백업을
거부한다. 원본이 사라진 후 checkpoint 밖에서 발생한 미관측 쓰기는 판별할 수 없다.
정지 경계를 증명할 수 없거나 최신 관리 증거가 없으면 서비스 노출을 재개하지 않는다.
정상 운영 재개 후 다음 정비 때에는 **현재 활성 저장소를 새로운 원본으로 지정하고 모든
기록자를 다시 봉쇄**해야 한다. 이 실험기는 기존 원본에서 복구하는 1회 정비 흐름만 구성한다.

관리/Docker/root 권한과 공개 신뢰의 읽기 전용 배포는 신뢰 기반이다. 관리 키·anchor·public pin
전체를 함께 과거로 되돌리는 공격, 악성 호스트, 서명키 유출은 이번 방어 범위 밖이다.
새 앱 시작 경로가 gate를 우회하면 보장이 성립하지 않는다. 실제 운영 도입 전 외부 witness·
관리 영역 이중화와 배포 강제 정책을 연결하고 독립 검토해야 한다.

## 실패 시 동작

1. 기본 checkpoint 수명은 300초, 허용 설정 범위는 1~3600초다. 미래/만료·다른 앱/정책/registry·
   다른 source/세대·잘못된 키·변조/재생을 거부한다. 제어 파일과 최신 증거는 신뢰 저장소에서 보호한다.
2. 원본 DB를 덮어쓰지 않고 새로운 임의 ID의 격리 저장소만 만든다. 알려진 journal/inbox 스키마와
   전체 체인·보관 이력·SQLite 무결성을 확인한다. 알 수 없는 스키마는 자동 마이그레이션하지 않는다.
3. 재시도는 이전 admission pin을 먼저 차단한다. 회수·용량·저장 실패 시 부분 사본은 남을 수 있지만
   승인 서명이 없으므로 시작할 수 없다. 임의 SQL 수정·이력 삭제로 검사를 통과시키지 않는다.
4. 복원 전 세션은 회수 상태여야 한다. 정상적인 이후 감사 항목은 원래 서명된 journal prefix를
   유지하면 재시작을 허용한다. 예전 사본의 pin 재사용·prefix 축소/변조·registry 교체는 거부한다.
5. 앱 기동 gate는 검사한 DB/registry 경로와 실제 앱 설정의 일치, API 키 인증·rule 분석기를 확인한다.
   오류는 고정 메시지로 종료하며 HTTP 기동은 승인 이후다. production 모드 실행은 거부한다.

단일 DB 상한 32 MiB, envelope 64 MiB의 소규모 로컬 프로필이다. 전체 파일/상태를 메모리에서
검증하므로 대용량 처리 성능이나 운영 SLA를 뜻하지 않는다. Docker 평문 임시 사본은 `/tmp` tmpfs,
Windows 단위 시험은 합성 데이터 임시 디렉터리를 쓴다. 보안 삭제 보장은 하지 않는다.

## 재현

Docker Desktop의 기존 사용자 컨테이너/데몬을 재시작하지 않는다. 호스트 포트·클라우드·유료 LLM·
Docker socket을 worker에 연결하지 않는다. 이미지 빌드 시 공개 패키지를 받을 수 있다.
실험은 무작위 소유 label이 붙은 자체 자원만 만들고 finally에서 ID/label 확인 후 정리한다.

```powershell
docker build --file Dockerfile --tag week3-app-recovery:app .
.venv/Scripts/python.exe -m scripts.test_app_recovery_runtime --image week3-app-recovery:app --directory runtime/week3/reproduce01
.venv/Scripts/python.exe -m pytest tests/test_app_state_recovery.py -q
```

출력 경로는 존재하지 않는 새 `runtime/week3/...`를 사용한다. 상세 평문·합성 토큰·개인키는
공개 문서/저장소에 넣지 않는다. `verification.json`은 비밀을 제외한 선택 지문·판정·시간만 담는다.
실행기는 이미지 안의 앱/새 스크립트 지문을 현재 소스와 대조하고 다르면 거부한다.
CI도 현재 소스에서 빌드한 앱 이미지로 보강된 18개 실험을 실행한다.

## 측정 정의와 근거

- `backup`: checkpoint 대조·SQLite 복사·암호화·저장과 해당 Docker job 시작 시간을 포함한다.
- `restore`: 복호화·격리 복원·모든 기존 세션 회수·승인 검증과 job 시작 시간을 포함한다.
- `restore_to_http_ready`: 원본 DB 유실 주입 직후부터 복원·고정 시각 검사·실제 앱 HTTP 준비까지다.
  fault 탐지 시간과 사람의 의사결정 시간을 포함하는 운영 RTO는 아니다.
- `rpo_at_stopped_checkpoint_records=0`: 정지된 최신 증거 경계에서 확인한 보안 journal 레코드 손실 0이다.
  실행 중 임의 시점이나 JSONL까지 RPO 0이라고 주장하지 않는다.
- 각 컨테이너 제한은 CPU 1 / memory 256 MiB / pids 128이며 호스트·캐시·부하에 따라 시간이 달라진다.

초기 PR #30 측정은 [초기 로컬 검증 JSON](infrastructure-results/app-state-recovery-20261105.json)을 따른다.

| 로컬 Docker 1회 측정 | 결과 |
|---|---|
| 통합 검사 | 15/15 통과 |
| SQLite 평문 크기 / 원본 journal | 49,152 bytes / 18 records |
| 최신 checkpoint / 백업 job | 2.5179초 / 2.4695초 |
| 복원·회수·승인 job | 2.4331초 |
| DB 유실 주입 후 HTTP 준비 | 11.033초 |
| 정지 증거 경계의 journal 손실 / 복원 전 세션 회수 | 0 records / 3개 |
| 실험 후 남은 소유 컨테이너 / 볼륨 | 0 / 0 |

Linux 전체 회귀는 **1,940개 통과 / 기존 경고 2개 / 467.84초**다. 복구 신규 단위 시험 48개를 포함한다.
후속 PR/최종 병합 후의 전체 회귀·기존 mTLS 41개·보강 복구 18개 결과와 정확한 commit/run은 PR 기록에 남긴다.
경고는 FastAPI/Starlette TestClient의 httpx 사용과 Mangum event loop deprecation이며 억제하지 않았다.

로컬 기록의 `base_git_head=a1f6046...`, `source_dirty=true`는 구현 중 시험했다는 뜻이다.
새 스크립트와 앱은 이미지/호스트 지문을 대조했고, 최종 PR 및 병합 후 CI는 각각의 checkout에서
같은 실험을 다시 실행한다. 로컬 1회를 운영 성능/HA 보장이나 평균/백분위 수치로 표시하지 않는다.

합성 fixture는 Ed25519로 실제 검증한 신호의 세션 3개(소비/기존 회수/미소비), 압축 journal,
완료·처리 중·대기 inbox와 압축 dedupe 이력, 비활성 신호 키를 포함한다. 같은 고정 시각에서
봉쇄하지 않은 대조 사본의 미소비 권한이 허용되는지 먼저 확인한다. 복원 사본은 같은 시각에도
`SESSION_NOT_AUTHORIZED`, 실제 API 키 HTTP 요청도 403/같은 사유여야 한다.
만료에 의한 우연한 거부나 예외 종료만으로 합격 처리하지 않는다.

## 3주차 잔여와 인계

| 계획 항목 | 이번 시점 판정 | 다음 완료 조건 / 담당 |
|---|---|---|
| I4 앱 SQLite 정비 백업·복구 실행/측정 | 본 문서의 로컬 범위 구현·검증 | 김택희: 상태 의미·최신 증거/중복·회수 독립 대조 |
| 앱 전체 저장 일관성 | 미완료 | JSONL 사건/감사/outbox 포함 스냅샷 계약·미전달 outbox 처리: 김택희와 합의 후 채희주 실행 |
| 선정 인프라 통합·고정 | 개별 mTLS/CA/프록시 검증은 선행, 통합 인수 미완료 | C01/C02 실제 채택 경로 버전/환경 lock·통합 실패 조건·회귀 증거: 채희주 |
| C01 관측 선정 | 로컬 잠정 선정 | 운영 인증/고부하 조건·독립 재현 후 조건부 채택 근거: 채희주, 김택희 교차 검토 |
| C02 HTTP PEP 선정 | NGINX 로컬 잠정 | 현재 mTLS 경로·버전의 인수 기준/운영 한계 정리: 채희주, 앱 계약 김택희 |
| C03 공급망 선정 | 비교·패치·잔여 위험 근거 있음, 최종 선정 미완료 | 잔여 CVE·검사 차이의 처리 기준/차단 정책·독립 입력 영향 검토 후 판정 |

기존 [개인 계획](roles/chaeheeju.md)·[멘토링 계획](mentoring-priority-roadmap.md)·
[역할 표](역할분담_주간계획_한눈에보기.md)의 마감(11/29 동결·12/6 제출 가능본)은 유지한다.
성능/정밀도·재현율·F1·오탐률 기준선은 수정하지 않았다. 이번 인프라 검사 수는 탐지 품질 지표가 아니다.
팀원 작업이나 독립 검토를 완료로 대신 기록하지 않는다.

## 설계에 사용한 공식 자료

- [Python sqlite3 backup/연결 수명](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup):
  일관된 복사는 backup API로 수행하고 연결은 명시적으로 닫는다. 복사 자체가 최신 보안 상태 증명은 아니다.
- [cryptography AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM):
  기존 CA recovery 암호화 primitive를 재사용하며 별도 키·임의 nonce·목적별 인증 manifest를 쓴다.
