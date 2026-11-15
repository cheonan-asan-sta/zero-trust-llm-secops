# 실행 근거의 보관·암호화 백업·복원·경보 연결

2026-11-16 v84 최신 aitest 통합·로컬 인수 완료: [outbox 경보·전체 암호화 백업·복원 후 정리](extra-exec-outbox-recovery.md). 집중331·전체5,770·실제 systemd36조건·실제 관측8조건 통과. 실제 실행4건 전체 byte 동일 복원, 게시3건만 정리·미게시1건 보존. 기존1,681,815건 결정 동일·추가 FP/기존 TP 손실0, 독립 F1 개선은 아니다. 팀원 PR59 대시보드 보존. AWS/유료 API0·8시간 soak 유예. 게시/CI/병합은 후속 PR 기록을 따른다.

2026-11-15 · v83 · 로컬 구현·묶음 검증 완료 · GitHub 미업로드·미병합

채희주의 인프라 실행·측정 범위에서 v82의 관리 실행 근거를 기존 보관·복구 흐름으로 연결한다. 직전 로컬 커밋 `a49a236`을 기반으로 `feature/chaeheeju-exec-evidence-retention`에서 진행한다. v82와 이번 후속은 아직 GitHub 업로드·병합하지 않았다. 팀원 대시보드와 탐지 모델·임계값은 변경하지 않는다.

## 이전과 달라진 점

| 구간 | v82 | v83 |
|---|---|---|
| 실행 근거 | worker의 요청 SHA·event·runtime proof·종료 코드 | 별도 authorization proof·호출자 영수증·앱 접근 이력 지문까지 한 봉투에 결속 |
| 보관 호환성 | worker 파일은 기존 archive 형식과 다름 | 새 봉투를 기존 archive가 구조 검증하고 원본 bytes 그대로 압축 보관 |
| 게시 실패 | worker와 브로커에 각각 근거 존재 | 개인 sealed outbox를 먼저 fsync하고 동일 원본 게시만 재시도 |
| 복구 | 기존 runtime snapshot 대상 | 새 완결 묶음도 기존 AES-256-GCM·외부 checkpoint/manifest pin·격리 복원으로 검증 |
| 현재성 검증 | runtime 출처 중심 health | 새 형식은 현재 caller pin·브로커 봉인·별도 정책 proof도 필수. pin이 없으면 unavailable |
| 관측 연결 | 별도 집계 fixture의 백업 경보 시험 | 실제 관리 실행 3건→콜드 2건→백업·복원→공개 집계를 실제 Prometheus/Alertmanager/수신기에 전달 |

## 데이터와 처리 순서

1. v82의 `AppExecutionGate`가 현재 앱 권한을 한 번 소비하고 고정 unit을 실행한다. 기존 person·responder·내부 READ·신호 출처 검사를 유지한다.
2. `seal_completed`가 실제 worker 파일과 브로커 결과, 앱 access 원장의 정확한 요청 SHA·주체·세션·자원·행위·버전을 대조한다. 원장 행 전체의 SHA를 남기되 원문 주체·세션 ID·grant hash·token은 봉투에 복사하지 않는다.
3. 새 `zt-managed-exec-capture-1`에는 요청, event, runtime/authorization proof, caller receipt, 앱 사용 영수증, 종료 코드와 봉인 시각이 들어간다. 브로커 Ed25519 키가 전체를 서명한다. 요청의 난수 nonce는 인증 결속용 공개 challenge이며 bearer credential이 아니다. 그래도 봉투는 0700/0600 개인 영역에서만 보관한다.
4. `dispatch_and_retain`은 archive와 분리한 개인 outbox에 원본을 독점 생성·fsync한 후, 기존 `capture_store_lock` 아래 request ID 폴더의 `capture.json`과 `latest.json`을 게시한다. run ID 충돌·symlink·예상 밖 파일·다른 scope를 거부한다. 오래된 outbox 재게시가 최신 기록을 되돌릴 수 없다.
5. `CaptureArchive`는 기존 snapshot 봉투와 새 봉투를 함께 지원한다. 기존 보호 최신본·용량·commit/readback 후 hot 삭제 계약을 유지한다. 보관은 구조/해시 무결성 검증이며 현재 신뢰 재인증이 아니다.
6. 기존 `CaptureBackup`이 콜드 SQLite만 암호화하고 외부 checkpoint와 manifest pin으로 격리 복원한다. hot/latest와 개인 outbox는 암호화 백업 대상에 자동 포함되지 않는다. 새 봉투를 재발급하거나 과거 시각을 바꾸지 않는다.
7. `CollectorMonitor`와 `service_capture_status`는 새 봉투에 service/caller 관리자 pin을 모두 요구한다. 현재 출처·키·정책과 원본 서명을 재검증한다. 복원된 오래된 자료는 stale 또는 unavailable이며 실행 권한이 아니다. read-only health는 grant·브로커·관측 결합 원장을 갱신하지 않는다.
8. 기존 keyless backup status는 실제 암호문·manifest·checkpoint·복원 원장을 재검사하고 개인 정보 없는 집계만 공개한다. 기존 opt-in exporter/인증 scrape/Alertmanager 경보 계약을 재사용한다. 실제 암호문 손상→unavailable→동일 에피소드 해제와 원본 복원 시각 경과 경보를 별도로 확인한다.

```mermaid
flowchart LR
  A[현재 앱 권한 소비 + 고정 실행] --> B[실제 exec 근거 + caller 영수증]
  B --> C[앱 이력 대조 + 브로커 봉인]
  C --> D[개인 sealed outbox]
  D --> E[공유 lock 아래 hot/latest 게시]
  E --> F[기존 콜드 archive]
  F --> G[AES256GCM + 외부 pin]
  G --> H[격리 review 복원]
  H --> I[원본 bytes/시각 검증]
  I --> J[공개 집계 → exporter → 경보]
```

## 운영자 연결과 재시도

새 ptrace exec 근거는 봉인을 제거해 예전 snapshot 봉투로 재포장해도 거부한다. 호출자/앱 근거 검증을 옛 형식으로 우회할 수 없다. 기존 native journal·manager snapshot의 보관 호환성은 유지한다.

기본 설치·타이머 활성화는 수행하지 않는다. 브로커를 운영에 연결할 때 기존 `gate.dispatch(...)` 대신 서버 전용 `dispatch_and_retain(gate, launcher, policy_proof, root, outbox)`를 선택한다. 두 경로의 동시 호출은 금지한다. 실행 실패나 게시 실패를 명령 재실행으로 복구하지 않는다.

게시가 중단됐으면 개인 outbox의 동일 파일만 다시 게시한다. 아래 값은 관리자가 고정할 예시이며 shell 명령·argv를 입력받는 API가 아니다.

```sh
python -m scripts.service_capture_retain \
  --capture /var/lib/secops-outbox/REQUEST_ID.json \
  --root /var/lib/secops-evidence/INSTANCE \
  --registry /etc/secops/service-registry.json --registry-sha256 SERVICE_PIN \
  --caller-registry /etc/secops/caller-registry.json --caller-registry-sha256 CALLER_PIN
```

기존 `service_capture_status` health 명령에는 `--caller-registry`와 `--caller-registry-sha256`를 함께 추가한다. 기본 환경은 실제 `oidc`이며, 테스트에서만 `--caller-environment local_oidc`를 명시한다. 기존 legacy snapshot은 caller pin 없이 동작한다. archive/backup/status CLI에는 새 key나 복호화 bypass를 추가하지 않았다.

## 묶음 검증과 판정 비교

| 검증 | 최종 결과 |
|---|---|
| Ruff·RUF100 | 전체 통과 |
| 집중 Linux | 456개 통과, 전체의 부분집합. 새 계약40개 포함 |
| 전체 Linux | 5,712개 통과, 실패·skip0. 사전 인수 후 한 번 실행 |
| 실제 systemd·ptrace | 24조건 통과. 실제 실행3건, 콜드2건, 원본 byte 동일 복원2건 |
| 실제 관측·경보 | 29조건 통과. 실제 복원 집계 연결6조건과 기존 별도 집계 고장 주입23조건 |
| 기존 판정 대조 | 1,681,815건 전후 결정 SHA 동일, 새 FP0·기존 TP 손실0·라벨 재열람0 |
| 비용·정리 | AWS·유료 API0. 소유 컨테이너·프로세스·unit·개인 임시 키/상태·소스 스냅샷 정리 |

집중·native·경보를 먼저 통과한 소스 archive `72eae861b697e7842ca94282657ea2e89d1dcd60bdaff33b3ac69b5c1dad469d`를 그대로 복사해 전체 회귀와 판정 비교를 수행했다. 이미 통과한 사전 검사를 불필요하게 반복하지 않았다. 동일 코드/설정 지문과 실패 이력은 [공개 결과 JSON](infrastructure-results/extra-exec-evidence-retention-v83-20261115.json)에 남겼다. 결과 문서만 검사 후 갱신했다.

| 기존 개발 기준선 | F1 이전→이후 | FP 이전→이후 | FN 이전→이후 |
|---|---:|---:|---:|
| 공유 서버 감사 | 0%→0% | 24→24 | 6→6 |
| 웹 서버 감사 | 70.77%→70.77% | 37→37 | 1→1 |
| 인증 | 95.08%→95.08% | 0→0 | 3→3 |

기존 출처 R/S/F/H의 결정을 그대로 보존했다. 위 세 영역의 개발 기준선은 유지되며 새 독립 채점이 아니다. 새 실행 근거의 수집·보관 기능이 과거 공개 로그에 없던 주체·명령을 사후 복원하거나 F1을 높였다고 주장하지 않는다. 여섯 영역 목표는 여전히 미달이다.

실제 경보 연결에서는 실제 암호문을 손상시켜 생성한 unavailable 집계가 수신기에 도달하고, 실제 복원 재검증 집계로 같은 에피소드가 해제됐다. 원래 복원 시각을 바꾸지 않고 실제60초 경과를 기다려 연령 경보를 확인했다. 연령 경보 해제는 테스트 프로필의 허용 연령을 명시적으로 늘린 것이며 새 복원을 수행한 것이 아니다. 추가23조건은 기존 별도 합성 집계의 고장 주입이며 이중으로 실제 실행 건수에 합산하지 않는다.

초기 집중 검사에서 Linux symlink 거부 예외 기대와 추가 CLI 검사의 pin 속성 참조를 바로잡았다. native 단계에서는 DrvFS 출력 폴더 권한을 기존 게시기가 거부했다. 검사 조건을 완화하지 않고 개인 Linux 경로에서 게시·검증한 공개 bytes만 Windows 결과 폴더와 관측 컨테이너에 전달했다. 보관 결과를 상태 보고 형식으로 변환할 때 ready 상태도 명시했다. 추가 검토에서 새 봉인을 제거해 legacy 봉투로 재포장하면 호출자 검증을 건너뛰는 경로를 발견했고, ptrace 실행 근거는 예전 형식으로 수용하지 않도록 차단·회귀 검증했다. 이전 전체 검사 게이트는 변경된 소스를 거부했으며, 최종 스냅샷에서 사전 인수 후 전체를 한 번 실행했다. 중간 실패·미실행 게이트는 성공으로 덮어쓰지 않았다.

## 경계와 미완료

- 실행과 앱 원장, outbox, archive는 하나의 분산 트랜잭션이 아니다. 실행 후 봉투가 outbox에 내구 저장되기 전 crash는 운영자가 worker·브로커·앱 원장을 대조해야 한다. 자동 재실행하지 않는다.
- outbox는 명시적 운영자 보존·정리 대상이다. 저장 가능 파일 수를 제한하고 꽉 차면 새 dispatch를 거부한다. 콜드 백업 검증만으로 모든 hot/outbox가 백업됐다고 말하지 않는다. pending outbox 전용 원격 경보와 자동 정리·외부 저장소 전송은 아직 없다.
- 봉인은 브로커가 확인한 앱 원장 행의 지문을 결속한다. 독립 앱 서명이나 원장 전체 포함·원격 불변 보관·특권 운영자 rollback 방지는 아니다. broker/runtime/authorization 키의 역할을 분리하지만 관리자·브로커·OS는 신뢰 경계다.
- 초기 관리 exec만 수집한다. 전체 호스트/자식 프로세스 감사, 실제 조직 SSO·실제 EDR, 운영 설치·AWS 배포·다중 호스트 백업은 별도다.
- 실제 실행 수집은 제한 권한의 root tracer를 쓰고 대상 자식은 비root다. Linux 회귀와 관측 컨테이너는 비root·network none이다. AWS·유료 LLM 호출은 없다.
- 실제 실행부터 복원 집계까지와 집계부터 경보 수신까지는 파일로 연결한 로컬 인수다. 운영 mTLS 다중 호스트 전체 경로를 재현했다고 쓰지 않는다. 추가 경보 고장 주입은 별도 집계 fixture다.
- 8시간/12시간 장기 시험은 사용자 요청대로 계속 유예한다. 탐지 정책·정답·평가 모집단을 이번 보관 작업에 맞춰 수정하지 않는다.

## 구현과 관련 자료

- [봉투/서명 검증](../scripts/f1_lab/managed_exec_capture.py), [서버 게시 어댑터](../scripts/f1_lab/managed_exec_retention.py), [안전한 재게시 CLI](../scripts/service_capture_retain.py)
- [집중 계약 검사](../tests/test_managed_exec_retention.py), [실제 실행 보관/복원 인수](../scripts/f1_lab/managed_exec_retention_controls.py), [경보 흐름](../scripts/run_collector_alert_flow.py)
- [직전 실행 이력·앱 정책 연결](extra-exec-history-app-binding.md), [기존 콜드 보관](extra-capture-archive.md), [암호화 백업](extra-capture-backup.md), [백업 복원 상태](extra-backup-recovery-status.md), [현재 성능](extra-current-performance.md)
