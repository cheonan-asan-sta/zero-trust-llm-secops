# 백업과 복구 검증 상태 지표 및 경보

2026-11-15 v83 로컬 완료·미병합: [실행 근거 보관·암호화 백업·복원·경보 연결](extra-exec-evidence-retention.md). 집중456개·전체5,712개·실제 systemd/ptrace24조건·관측29조건 통과. 실제 실행3건에서 콜드2건을 byte 동일 복원하고 실제 복원 집계를 경보로 연결했다. 기존1,681,815건 판정 동일·새 FP/TP 손실0, 독립 F1 개선은 아니다. AWS/유료 API0, 8시간 유예. v82의 보관 연결 후속은 이 결과로 갱신한다.

2026-11-15 · v81 · 채희주 인프라 담당 · 기준 aitest `66c0422` · [8시간 시험 유예 기록](extra-systemd-soak.md)

암호화 백업과 격리 복원 결과를 주기적으로 확인하고, 확인할 수 없거나 오래된 근거에 경보를 연결했다. 이번 로컬 검증은 완료했다. 운영 배포와 독립 탐지 성능 평가는 별도이며, 8시간 시험은 재개하지 않는다.

## 이번 결과

| 검증 | 확인한 결과 |
|---|---|
| 집중 및 전체 로컬 | 집중 196개와 전체 5,623개 통과, Ruff와 RUF100 통과. 집중 시험은 전체의 부분집합 |
| 실제 systemd | 기존 63조건과 새 상태 작업자 8조건, 총 71조건 통과 |
| 작업자 권한 | 기존 daemon UID1, effective 및 bounding capability 0, NoNewPrivileges. LoadCredential 두 종류의 정의 개수 0 |
| 실제 상태 확인 | 올바른 pin에서 verified, 잘못된 pin에서 빈 unavailable, 올바른 설정 복구 후 정상 상태 |
| 실제 timer | 소유 fixture의 1초 치환 주기로 확인 시각 3개 이상 관측. 원래 snapshot·백업·복구 시각은 유지 |
| 관측 도구 흐름 | 캐시 Prometheus 3.15.1, Alertmanager 0.34.2와 인증된 로컬 webhook의 23조건 통과 |
| 근거가 오래된 경우 | snapshot과 복구 검증 시점의 기간 초과를 각각 전달하고, 회복 후 같은 경보 episode 해제 |
| 보고자 중단 | 실제 180초 만료 후 과거 성공 개수 제거와 경보 전달, 재개 후 같은 episode 해제 |
| 기본 동작과 인증 | 옵션을 주지 않으면 새 지표·경보 없음. 인증 없는 scrape는 401, 기존 mTLS 경로 유지 |
| 기존 판정 | 1,681,815건의 결정 SHA 동일, 새 FP 0, 기존 TP 손실 0, 라벨 재열람 0 |
| 비용과 정리 | AWS·유료 API 0. 소유 컨테이너·프로세스·unit·상태·설정·소켓·자격·WSL 소스 정리 |

실제 systemd 시험은 암호화 package와 격리 복원 DB를 사용했다. 관측 도구 시험은 **별도의 제어된 집계 fixture**를 사용했다. 두 결과를 실제 원본부터 운영 mTLS 경보까지 연결한 통합 E2E 인수로 표현하지 않는다.

### 실패 보존과 스냅샷 관계

첫 native 실행에서 작업자는 정상 검증했고 권한도 예상대로였으나, 인수 도구가 복합 속성의 `LoadCredential=[unprintable]` 문자열을 판독하지 못해 실패했다. 이를 빈 값으로 간주하지 않았다.
첫 보완에서는 typed D-Bus 조회를 추가했지만, 짧은 oneshot이 종료된 뒤 GetUnit 조회가 실패했다. 소유 임시 unit에서 종료 뒤 조회 실패와 RemainAfterExit 상태의 빈 배열 조회를 재현했다.
최종 인수 도구는 **검사 fixture에만** RemainAfterExit를 적용해 설치 fragment와 typed 빈 목록을 확인한다. 실제 timer 시험 전에는 원래 oneshot으로 복구하고 `RemainAfterExit=no`를 확인한다. 운영 service 템플릿에는 이 유지 설정을 추가하지 않았다.

전체·판정 비교·관측 흐름의 스냅샷 A와 최종 집중·native 스냅샷 B는 `scripts/f1_lab/backup_recovery_status_runtime.py` 한 인수 도구 파일만 다르다. 운영 worker·exporter·경보 규칙·템플릿은 바뀌지 않았다.
최종 스냅샷에서 집중 196개와 native를 재검증했고, 같은 제품 코드로 통과한 전체·판정 비교·관측 결과는 보존했다. 최초 두 native 실패와 정리 결과도 원시 근거에 남겼다. PR CI는 이 로컬 검증과 별도로 확인한다.

## 검증하는 근거

[검증 모듈](../scripts/f1_lab/backup_recovery_status.py)은 package의 manifest와 암호문만 허용하고, 운영자가 별도로 보존한 manifest·checkpoint·restore receipt의 pin을 대조한다. 암호문 크기와 SHA, scope와 최소 이력, 복원 DB의 원본 캡처 전체 및 receipt와 manifest의 결속을 확인한다.
이번 상태 확인은 복구키를 받거나 AES-GCM 복호화를 새로 수행하지 않는다. 기존 restore가 인증 복호화한 결과와 현재 pin 및 바이트 동일성을 확인한다. 현재 복구키의 가용성이나 실제 재해 복구 성공을 새로 증명하는 작업은 아니다.
패키지가 자신의 pin을 선택하거나 최신 디렉터리를 자동 승격하지 않는다. 외부 pin과 호스트·작성자는 신뢰 전제이며, root 장악이나 전체 이력 rollback을 막는 외부 attestation은 아니다.

`snapshot_at ≤ backup_at ≤ restored_at ≤ checked_at`를 확인한다. 재검증은 checked_at만 갱신하고 나머지 세 시각은 보존한다. 반복 확인으로 오래된 백업이나 복구 시험의 나이를 줄이지 않는다.

## 공개 상태와 경보

공개 파일은 최대 8KiB와 0644 권한으로 게시한다. scope SHA, 시각, 개수·바이트와 두 false 권한 플래그만 담고, 키·서명·본문·원래 신원·경로·pin은 내보내지 않는다.
검증 실패는 값이 비어 있는 unavailable로 게시한다. 파일 부재·손상·scope 불일치·미래 시각·180초 만료에는 과거 성공과 개수를 재사용하지 않는다. 게시 자체가 실패해도 이전 보고서의 만료 시각은 유지한다.

| 지표 또는 경보 | 의미 |
|---|---|
| secops_capture_backup_status_success | 현재 유효한 보고서에서 pinned package와 복원 DB 확인에 성공 |
| secops_capture_backup_recovery_recent | 위 확인에 성공하고 snapshot과 복구 시점이 각각의 기간 한도 안에 있음 |
| snapshot_age_seconds, restore_age_seconds | 원래 근거 시각에서 계산한 나이 |
| records, raw_bytes | 검증된 cold 자료의 개수와 바이트. hot/latest 전체의 백업 완료를 뜻하지 않음 |
| C01CaptureBackupVerificationUnavailable | 명시적으로 활성화한 bridge에서 확인 불가·보고서 만료가 2초 지속 |
| C01CaptureBackupRecoveryOverdue | 무결성 확인은 성공했지만 snapshot 또는 복구 시점이 기간을 초과한 상태가 2초 지속 |

기간 한도는 운영자가 정하는 exporter 프로필로 고정한다. 모든 상태는 운영 확인용이며 접근 허용·자동 차단 권한이 아니다. automatic_activation_allowed와 authenticity_or_freshness_asserted는 항상 False다.

## 사용 예시

```text
python -m scripts.capture_backup_status --tenant <tenant> --server <server> --unit app.service --source <collector> --backup <package> --manifest-sha256 <외부SHA> --checkpoint <checkpoint> --checkpoint-sha256 <외부SHA> --review <격리restore출력> --receipt-sha256 <외부SHA> --status-file <별도공개디렉터리/status.json>
python -m scripts.signal_metrics_exporter <기존옵션> --backup-recovery-profile <읽기전용profile.json>
```

```json
{
  "schema": "zt-backup-recovery-metrics-profile-1",
  "scope_sha256": "<scope_hash(ArchiveScope)의SHA256>",
  "status_file": "/collector/status/backup-recovery.json",
  "max_snapshot_age_seconds": 86400,
  "max_restore_age_seconds": 604800
}
```

위 1일·7일은 설정 예시이며 운영 SLO 선정 결과가 아니다. snapshot 한도는 60초~7일, 복구 한도는 60초~30일을 명시한다. 프로필은 시작 시 고정하고 변경 시 exporter를 재시작한다.
공개 부모 디렉터리는 별도 0755로 준비한다. exporter에는 집계와 프로필만 읽기 전용으로 마운트하고 private package·checkpoint·review DB·키를 마운트하지 않는다. 공개 출력은 private 입력 경로의 내부나 상위에 둘 수 없다.

## 선택형 systemd 실행

[service](../infra/systemd/secops-capture-recovery-status@.service)는 기존 collector 계정, NoNewPrivileges, capability 0, PrivateNetwork, read-only, memory 512MiB, Tasks 16과 시작 60초 제한을 사용한다. 복구키 credential은 요구하지 않는다.
공개 collector.conf와 capture-recovery-status.conf에 scope와 검토된 절대 경로·외부 pin을 둔다. 백업·checkpoint·복원 root는 읽기 전용이다. 먼저 수동 verify로 만든 `restored/review/.capture-store.lock`만 쓰기 예외다. 비표준 경로에는 별도 override와 인수가 필요하다.
[timer](../infra/systemd/secops-capture-recovery-status@.timer)는 부팅 30초 뒤와 60초 주기로 **기존 근거의 확인만** 수행한다. 새 백업 생성·복원·키 회전·checkpoint 승격 일정은 추가하지 않았다.
운영 설치·enable·실제 계정 생성·지속 mTLS mount와 lock 활성화는 수행하지 않았다. 로컬 fixture의 치환 경로·기존 daemon 계정·가속 주기를 운영 인수로 확대하지 않는다.

## 남은 작업

| 범위 | 미완료 항목 |
|---|---|
| 장기 안정성 | 8시간·12시간 연속 시험 유예. 이번 180초 만료 관측으로 대체하지 않음 |
| 운영 복구 체계 | 복구키 보관·회전, 외부 pin 보관·갱신 검토, 원격 보관·보존 정책, 실제 백업·복구 훈련 일정 |
| 운영 활성화 | exporter/mTLS mount와 lock, 실제 경보 수신자, 권한·경로·주기·용량과 팀 교차 인수 |
| 실행 이력과 신원 | kernel EXECVE 수집, 실제 조직 SSO·앱 정책 연결 |
| 품질 평가 | 새 독립 자료와 라벨 검토. 기존 개발 결과를 새 독립 평가로 재사용하지 않음 |

공유 감사 F1 0%·FP24/FN6, 웹 감사 F1 70.77%·FP37/FN1, 인증 F1 95.08%·FP0/FN3의 개발 기준선은 유지했다. 인프라 검증을 독립 탐지 목표 완료로 계산하지 않는다.
탐지·LLM·라벨·PDP/PEP와 팀원 Draft PR59는 변경하지 않았다. Codex 보조 구현·실행이며 팀원의 독립 검토나 운영 승인이 아니다.

- [공개 결과와 스냅샷·소스 지문](infrastructure-results/extra-backup-recovery-status-v81-20261115.json)
- [systemd 255 D-Bus](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.systemd1.html), [busctl JSON](https://www.freedesktop.org/software/systemd/man/255/busctl.html): 자격 속성을 typed 배열로 확인하는 근거
