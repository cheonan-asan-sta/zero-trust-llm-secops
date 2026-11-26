# 복원 검증 집계와 보관 실패 경보

2026-11-20 · `extra` · 구현 `1c98687`. [키 없는 복원 재검증](extra-witness-restore-inspection-20261120.md)을 기존 인증 exporter/Prometheus/Alertmanager에 선택적으로 연결했다. [08:00까지의 목표](extra-until-0800-20261120.md)는 진행 중이다. 수집/서명 시각 경계와 중단 후보의 명시적 재개 점검을 이어간다.

## 검증·관측·점검 기한을 구분

생산자는 보관한 package/완료 receipt/profile/최소 영수증 pin을 검증해 공개 집계를 게시한다. exporter는 이 집계만 읽고 암호화 패키지·복원 DB·개인키를 열지 않는다. 집계에는 raw 명령·이벤트·사람·파일 경로가 없고 고정한 pin도 metric label로 내보내지 않는다. 기존 관측 상태와 별도 metric 이름을 사용한다.

집계 TTL은30초다. 손상·누락·다른 pin·미래/만료된 집계는 `secops_witness_restore_status_success 0`만 표시하고 예전 anchor/경과 시간 값을 재사용하지 않는다. 검증이 성공해도 실제 복호화/현재 원천 서비스 점검을 수행했다는 뜻은 아니다. `decryption_checked=false`, `live_source_checked=false`, `independent_storage_verified=false`, `automatic_activation_allowed=false`를 고정한다.

백업 생성 시각과 원래 복원 시작 시각으로 경과 시간을 계산한다. 반복 점검은 이 시각을 갱신하지 않는다. `restore_recent`는 운영자가 정한 백업/복원 점검 기한 이내인지 나타내며, 현재 원천 이벤트의 신선도나 실제 완료 시각의 독립 증명이 아니다. 현재 관측 상태는 기존 witness observation metric에서 별도로 확인해야 한다.

프로필에 없는 경우 기존 exporter 동작을 유지한다. 공개 파일 게시의 소유자·권한·잠금·시간 역행/다른 pin 거부·fsync 구현은 `status_publication.py`로 공유했다. 서로 다른 형식을 같은 validator로 통과시키지 않고 각각의 정확한 schema와 네 외부 pin으로 검증한다. 이전 관측 게시/HTTP 시험도 다시 통과했다. pin을 바꾸는 백업 갱신은 운영자가 승인한 새 프로필/상태 파일 경로가 필요하며 자동 재고정하지 않는다.

## 실행 예

생산자는 복구키를 요구하지 않는다. 이 게시와 실제 공개 파일 권한 계약은 Linux/POSIX에서 실행한다. Windows는 순수 검증/렌더링 시험이며 POSIX 보안 게시/운영 ACL 인수로 표시하지 않는다.

```bash
python -m scripts.witness_restore_status --package <package> --directory <검토-후보> --backup-sha256 <외부-package-pin> --restore-receipt-sha256 <외부-receipt-pin> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-최소-pin> --status-file <별도-공개-status.json>
python -m scripts.signal_metrics_exporter --upstream <기존-inbox-URL> --token-file <scrape-token> --witness-restore-profile <metrics-profile.json>
```

```json
{
  "schema": "zt-witness-restore-metrics-profile-1",
  "profile_sha256": "<64자리-profile-pin>",
  "minimum_receipt": "<64자리-minimum-pin>",
  "backup_sha256": "<64자리-package-pin>",
  "restore_receipt_sha256": "<64자리-receipt-pin>",
  "status_file": "/absolute/public/restore-status.json",
  "max_backup_age_seconds": 86400,
  "max_restore_age_seconds": 604800
}
```

위 기한은 구성 예시이며 기업 인수 기준으로 확정한 값이 아니다. 기존 exporter의 별도 upstream/scrape 자격증명과 TLS 계약은 유지한다. 검증 불가 경보는 critical, 보관/점검 기한 초과는 warning으로 추가했다. 키를 읽지 않는다고 독립된 권한/호스트를 마련한 것은 아니며 같은 호스트의 신뢰된 writer/configuration에 의존한다.

## 검증 근거

관련 묶음은 **Windows147통과·17제외, Linux164통과·제외0**. 신규 복원 집계27건에는 다른 네 pin·미래/만료·시각 역행·false flag/필드/카운터 변조, 점검을 반복해도 원래 시각 보존, 실제 CLI 실패/복구, 인증 HTTP와 기본 opt-out, 잘못된 profile 정책 거부가 포함된다. Windows17제외는 기존/신규 POSIX 파일 권한·게시 경로다. 전체 프로젝트 회귀나 독립 탐지 수치에 합산하지 않는다.

실제 로컬 수집기·원본 감사 DB·임시 개인키·AES-GCM 백업/복원 후보로 Prometheus/Alertmanager 흐름을 실행해 **18조건·장애4회**를 확인했다. 기존 관측 만료·서명키 부재·상태 파일 손상에 더해 **암호화 패키지 bytes 손상 → 복원 검증 불가 firing → 정확한 기존 bytes 복원 → 동일 fingerprint/starts_at resolved**를 확인했다. 매 장애에서 새 notification offset/job을 제한하고 원인 metric을 실제 query로 확인했다. 모니터링이 원래 복원 시작 시각을 바꾸지 않았고 원본 감사 DB도 그대로다. 모든 실험 프로세스/서버/임시 DB·키는 종료·정리했다.

`promtool check rules`와 **제어된 집계11시나리오**가 통과했다. 점검 기한 초과는 시각을 제어한 기능/규칙 시험이며, 실제 며칠의 보관 주기를 기다린 운영 인수나 실제8h soak는 아니다. 실제 네 장애 흐름은 한 호스트의 인증 loopback HTTP 시험이며 운영 mTLS 배포 검증과 구분한다.

원본·소스 지문은 [manifest](infrastructure-results/extra-witness-restore-monitor-20261120.json)에 있다. 기존 LLM F1 93.41%·재현율90.56%는 그대로이고 목표 미달이다. 모델/정답/분모 변경0, 새 유료/API/AWS/Docker/push/CI/병합0.
