# 실행 outbox 경보와 최신 원본 전체 백업·안전한 정리

v84 · 11월15~16일 개발 세션 · 로컬 묶음 인수 완료, 최신 aitest 통합 검증 전

채희주 담당의 v83 `00edfc6` 후속이다. [오전8시까지의 목표](extra-overnight-target-20261116.md)에 따라 outbox 잔여 항목부터 처리한다. AWS·유료 API·장기8시간 soak·운영 배포는 실행하지 않는다.

## 바뀐 동작

| 구간 | 이전 | 이번 연결 |
|---|---|---|
| 미게시 근거 | 개인 outbox와 명시적 재게시 CLI, 전용 경보 없음 | 현재 pin/서명·실제 hot/cold byte 대조를 통한 pending·게시·불가 상태 |
| 경보 | 기존 수집·콜드 백업 경보 | opt-in outbox 불가·미게시 장기 적체·개수 한도 경보, 보고 만료 시 이전 건수 제거 |
| 최신 원본 백업 | 콜드 DB만 암호화, 최신 hot/outbox 제외 | 전체 sealed outbox를 별도 개인 mirror DB로 보존해 기존 AES256GCM 엔진으로 백업·격리 복원 |
| 정리 | 수동 보존·정리 | 최소 보존 나이 + 게시된 동일 bytes + 외부 pin으로 검증한 격리 복원본이 모두 맞을 때만 제한 개수 정리 |
| 작업자 | 별도 outbox 상태 작업자 없음 | 서명/복구 개인키 없이 일반 계정·capability0·NNP 상태 점검, 선택형 service/timer 제공 |

실행 권한·명령 재시도·탐지 임계값을 추가하지 않는다. 확인된 원본 bytes만 보존·복구하며, 과거 시각·봉인·grant를 갱신하지 않는다.

## 처리와 제약

1. 생산자와 점검/정리 작업은 outbox의 동일 협력 lock을 사용한다. 파일 이름·소유 UID·0600·단일 링크·크기·scope·요청 ID를 확인한다. 알 수 없는 파일·중단 잔여 파일·서명 손상은 건너뛰지 않고 unavailable로 남긴다.
2. 상태 작업자는 개인키 없이 service/caller 관리자 pin과 전체 봉인을 검증한다. 실제 live hot 또는 검증된 cold DB와 원본 SHA가 같은지 확인해 게시 여부를 계산한다. 최신 `latest.json` 하나가 존재한다는 이유로 모든 근거가 게시됐다고 보지 않는다.
3. 원문 전체를 메모리에 쌓지 않고 순서대로 점검한다. 개수·raw 크기·점검 시간과 systemd CPU/메모리/시간 한도로 제한한다. 한도 초과는 정상0건이 아니라 확인 불가다.
4. `CaptureArchive.preserve`는 별도 mirror에 명시한 원본을 commit/readback한다. 입력을 삭제하거나 가짜 최신 이벤트를 만들어 보호 규칙을 우회하지 않는다. 최신·미게시 기록도 포함한다. mirror는 개인 평문 준비 영역이며 자체를 암호화 원격 사본으로 부르지 않는다.
5. mirror를 기존 `capture_archive_backup`의 checkpoint/backup/restore/verify 입력으로 사용한다. 기존 AES256GCM, 외부 checkpoint/manifest/receipt pin과 복구키 계약을 유지한다. source/outbox와 분리된 경로로 복원하며 자동 활성화하지 않는다.
6. 정리는 기본 preview이며 `--apply`일 때만 실행한다. 원래 봉인 시각을 기준으로 기본1일 보존한다. 현재 게시 원본과 pin 검증 복원본 둘 다 정확히 일치해야 한다. 미게시·최근·새로 생겨 백업되지 않은 파일·손상·다른 scope는 정리 대상이 아니다. 한 번에 기본64개/최대256개, 삭제 전 inode·크기·mtime·bytes를 재대조하고 fsync한다.
7. 공개 보고에는 scope SHA, 개수·크기와 가장 오래된 pending의 원래 시각만 나온다. 원문 ID·계정·명령·경로·token·키는 없다. 보고 유효기간은60초이며 exporter가 확인 시각을 갱신하지 않는다. 만료/확인 불가일 때 지난 건수를 내보내지 않는다.
8. 기본 exporter는 변경하지 않고 `--exec-outbox-profile`로 선택한다. 기존 인증된 scrape와 수신기를 재사용한다. 경보는 operational queue 상태이며 위협 오탐률/F1로 합산하지 않는다.

## 운영자 명령 연결

개인 owner가 일치하는 0700 디렉터리를 준비하고 관리자 고정 scope로 실행한다. 아래 `INSTANCE`·pin은 운영자가 정할 예시다.

```sh
python -m scripts.exec_outbox_snapshot \
  --tenant TENANT --server SERVER --unit UNIT.service --source SOURCE \
  --root /var/lib/secops-evidence/INSTANCE \
  --outbox /var/lib/secops-outbox/INSTANCE --mirror /backup/private/NEW-MIRROR
```

이 mirror에 `scripts.capture_archive_backup`의 기존 checkpoint → backup → 별도 restore → verify를 적용한다. 복구키는 기존 stdin/LoadCredential 경로를 쓰며 argv·환경 변수·공개 보고에 넣지 않는다. 이후 다음 명령은 기본 preview다.

```sh
python -m scripts.exec_outbox_prune \
  --tenant TENANT --server SERVER --unit UNIT.service --source SOURCE \
  --root /var/lib/secops-evidence/INSTANCE --outbox /var/lib/secops-outbox/INSTANCE \
  --review /backup/private/RESTORED --receipt-sha256 RESTORE_PIN \
  --checkpoint /backup/private/checkpoint.json --checkpoint-sha256 CHECKPOINT_PIN
```

정책·복원본을 대조한 뒤 관리자가 `--apply`를 명시할 수 있다. 상태·정리 service/timer를 선택형으로 제공하되 설치·enable하지 않았다. 정리 템플릿의 고정 review 경로는 `/var/lib/secops-outbox-review/INSTANCE`, checkpoint는 `/etc/secops/exec-outbox/INSTANCE-checkpoint.json`이며 운영자가 검증된 복원본과 pin을 명시적으로 준비한다. lock 파일은 producer와 verify로 먼저 생성한 소유자0600 파일이어야 한다. 상태 작업자의 쓰기는 lock과 공개 상태에만 허용하며 실행 근거는 읽기 전용이다. 키가 필요한 백업 timer와 자동 pin 승격은 추가하지 않았다.

outbox exporter 프로필은 다음 형식이다. 예시5초 임계값은 로컬 인수에서 실제 원래 pending 시각의 경과를 확인하기 위해 쓴다. 운영 임계값과 보존 정책은 별도로 정한다.

```json
{"schema":"zt-exec-outbox-metrics-profile-1","scope_sha256":"ADMIN_SCOPE_SHA256","status_file":"/var/cache/secops-exec-outbox/INSTANCE.json","max_pending_age_seconds":60,"max_records":10000}
```

## 묶음 인수 계획

집중 계약 검사·기존 보관/암호화/상태/exporter 회귀를 먼저 묶는다. 실제 systemd 관리 실행4건 중 게시 실패1건을 주입해 전체4건 백업/byte 동일 복원, 게시3건만 정리·미게시1건 보존, 같은 bytes 재게시·권한/명령 재사용 없음과 비root 상태 작업자를 확인한다. 기존 v83의3건을 재사용한 총4건이며 합산7건으로 쓰지 않는다.

공개 pending/unavailable/ready 보고를 같은 코드 스냅샷의 network-none 관측 컨테이너로 전달해 실제 경보·해제·원래 보고 시각60초 만료를 검사한다. 보존 나이 정리 시험은 제어된 함수 시각을 사용하고 실제60초 보고 만료와 구분한다. 사전 인수 후 같은 스냅샷으로 전체 회귀와 고정1,681,815건 결정 대조를 수행한다.

첫 로컬 확정 결과는 집중310·전체5,766·실제 systemd36조건·관측8조건 통과, 실패/skip0·기존1,681,815건 판정 불변·추가 FP/기존 TP 손실0이다. 모두 소스 archive `b777f34c7193923392701b8e221e7177191c3bde6f4a7f777eafc0f28e89929a`로 검사했다. 초기 native 인수에서는 시험용 파일이 패키지 부모 경로에 함께 쌓여 기존16개 제한에 걸렸다. 제한을 완화하지 않고 전용 패키지 폴더를 분리한 뒤 재검증했다. 소유 컨테이너·unit·키/개인 상태·스냅샷을 정리했다.

작업 중 원격 aitest에 팀원의 대시보드 PR59 `be25a5c`가 병합된 것을 확인했다. 위 결과는 통합 전 로컬 기준이며, 팀원 변경을 보존해 최신 aitest에 통합하고 별도 검증한 뒤 최종 결과와 게시·CI 상태를 기록한다. 이번 인프라 작업으로 기존 탐지 F1을 높였다고 표시하지 않는다.

## 계속 남는 항목

- outbox에 봉투가 저장되기 전 실행 직후 crash의 자동 대조는 다음 묶음이다. 자동 재실행·grant 환급은 하지 않는다. 중단 잔여 파일·알 수 없는 inventory는 수동 대조가 필요하다.
- 실제 외부/다중 호스트 저장소·운영 키/외부 pin 보관·독립 운영자 권한과 보존 정책 인수는 별도다. 같은 PC의 별도 경로 시험을 물리 장애 내성으로 바꾸지 않는다.
- 백업되는 것은 sealed outbox다. 아직 봉인되지 않은 worker/브로커/app DB와 그 사이의 intent는 이 패키지에 자동 포함되지 않는다. outbox에서 정리된 기존 cold DB는 기존 콜드 백업 흐름을 유지한다.
- 현재 pin이 바뀌거나 만료·회수되면 점검은 unavailable이다. 구조적 원본 복구/보존과 현재 신뢰 검증을 구분한다. 과거 신뢰 묶음의 외부 관리도 운영 인수 대상이다.
- 상태 작업자는 개인키 없이 실행되지만 해당 저장소 Unix owner의 읽기·협력 lock 권한이 필요하다. 실제 일반 계정 시험은 서명된 원본 사본에서 검증하며 운영 브로커/수집기 owner 이행을 자동 완료하지 않는다.
- 실제 조직 SSO·기기 신호·호스트 전체 실행 이력·운영 다중 호스트 mTLS와 새로운 독립 탐지 평가는 남는다. F1 개선이나 여섯 영역 목표 달성을 기능 시험으로 주장하지 않는다.

[직전 결과](extra-exec-evidence-retention.md) · [현재 성능](extra-current-performance.md)
