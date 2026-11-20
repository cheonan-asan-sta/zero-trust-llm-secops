# 감사 서명 기록의 운영자 승인 세대 전환

서명 기록 4,096개를 채운 세대에서 마지막 영수증까지 확인하고 대기 작업이 없으면 다음 세대로 전환할 수 있다. 이전 서명 저널과 확인 DB는 읽기 전용으로 검사한다. 새 키, 새 서명 저널, 새 확인 디렉터리를 사용하고 감사 원본, 스트림, 수집 정책은 이어받는다. 새 세대의 첫 서명은 이전 세대의 감사 지점과 시각을 하한으로 사용한다.

## 운영 절차

1. 기존 수집기를 정상적으로 정지한다. 기존 프로필 해시와 운영자가 보관한 **마지막으로 확인된 영수증 해시**를 준비한다. 마지막 영수증이 서명 저널에만 있고 확인 DB에 대기 상태가 남아 있으면 기존 수집기로 먼저 재개해 확인을 마친다.
2. 같은 감사 SQLite 경로와 스트림 ID로 새 서명 디렉터리를 만든다. 출력 파일의 상위 디렉터리는 수집 서비스 계정이 소유하고 보호하는 새 세대 전용 위치로 준비한다.

   ```text
   python -m scripts.audit_witness init --state-dir NEW_SIGNER --database AUDIT_DB --stream-id STREAM
   ```

3. 전환 계획을 읽고 이전 최종 영수증, 새 키 지문, 전환 기록 경로를 확인한다. 명령에 넣는 대문자 값은 운영자의 실제 경로와 외부 보관 해시다.

   ```text
   python -m scripts.audit_witness_rollover plan --old-control OLD_CONTROL --old-profile-sha256 OLD_PROFILE --old-terminal-sha256 OLD_TERMINAL --new-signer NEW_SIGNER --new-key-sha256 NEW_KEY --record GENERATION_JSON
   ```

4. 검토 후 명시적으로 승인한다. 승인 해시는 계획 문서의 전체 SHA-256이다. 이전 서명 디렉터리의 `rollover.approval`을 먼저 예약한다. 동일 서명 저널을 참조하는 확인 DB 사본에서도 서로 다른 후속 세대 예약은 거부된다. 승인 시 수집기를 시작하지 않고 전환 기록과 새 프로필·최소 영수증 해시를 출력한다.

   ```text
   python -m scripts.audit_witness_rollover approve --old-control OLD_CONTROL --old-profile-sha256 OLD_PROFILE --old-terminal-sha256 OLD_TERMINAL --new-signer NEW_SIGNER --new-key-sha256 NEW_KEY --record GENERATION_JSON --approval-sha256 APPROVAL
   ```

5. 출력의 `record_sha256`과 `minimum_receipt`를 별도 보관한다. 새 세대 수집 명령은 이 값을 받아 연결을 검증한 뒤 기존 수집 루프를 사용한다. 첫 영수증보다 최신의 최소 해시를 보관했다면 그 값을 사용한다. `--cycles 1`은 수동 확인 때만 붙인다. Linux에서 공개 상태를 새로 게시할 때는 `--status-file`을 지정하고 경보 쪽의 고정 프로필·최소 기준도 명시적으로 갱신한다.

   ```text
   python -m scripts.audit_witness_rollover verify --record GENERATION_JSON --record-sha256 RECORD_PIN
   python -m scripts.audit_witness_rollover watch --record GENERATION_JSON --record-sha256 RECORD_PIN --minimum-receipt MINIMUM
   ```

## 복구와 보관

- 승인 중 중단되면 같은 인수와 승인 해시로 `approve`를 재시도한다. 새 저널에 첫 서명이 이미 저장됐다면 동일한 첫 서명을 회수한다. 전환 기록이 게시됐다면 동일한 결과를 돌려준다. 확인 디렉터리는 고유 경로에 만들고 전환 기록은 기존 파일을 덮어쓰지 않는 방식으로 게시한다. 게시 전에 강제 종료되면 참조되지 않는 임시 디렉터리가 남을 수 있으므로, 운영자는 게시된 기록이 가리키는 경로를 먼저 확인한 뒤 정리한다.
- 승인 예약 뒤 감사 원본의 검증이 실패하면 원본의 올바른 이력을 복구하고 같은 승인으로 재시도한다. 다른 승인으로 교체하려고 예약을 삭제하면 전환의 단일 후속 세대 보장이 사라진다. 전환은 서명 저널의 용량을 새로 시작하며, 감사 원본 SQLite 자체의 보관·용량 정책은 별도로 운영한다.
- 이전 세대별 서명·확인 디렉터리, 공개키, 예약, 전환 기록과 외부 해시를 보존한다. 전환을 여러 번 했다면 보관한 기록을 세대 순서대로 각각 검증한다. 확인 DB 암호화 백업에는 전환 기록과 이전 서명 저널이 포함되지 않으므로 별도로 보관한다.
- 이 승인 방식은 로컬 운영자의 명시적 CLI 실행과 입력 해시에 의해 성립한다. 운영자 권한은 파일시스템 계정으로 통제한다. 동일 호스트 관리자가 보관 원본과 고정 해시를 모두 재설정하는 상황에 대비하려면 독립 보관이 필요하다.

## systemd와 경보 전환

승인에 성공한 뒤 수집 서비스 계정으로 Linux에서 아래 명령을 실행한다. `STATUS_DIRECTORY`는 수집기 계정이 소유한 해당 인스턴스의 전용 캐시 디렉터리다. systemd 설정에 쓰이는 경로는 공백과 specifier가 없는 실제 절대 경로로 준비한다.

```text
python -m scripts.audit_witness_rollover systemd-config --record GENERATION_JSON --record-sha256 RECORD_PIN --minimum-receipt MINIMUM --status-directory STATUS_DIRECTORY
```

이 명령은 `systemd_drop_in`과 `metrics_profile`을 한 JSON으로 출력한다. 운영자는 두 값을 같은 출력에서 가져와 다음 순서로 적용한다.

1. `systemd_drop_in`의 문자열을 실제 줄바꿈이 있는 UTF-8 파일로 추출한다. 예를 들어 생성 JSON에서 `jq -r .systemd_drop_in`으로 추출할 수 있다. 내용을 검토하고 `/etc/systemd/system/secops-audit-witness@INSTANCE.service.d/rollover.conf`에 관리 권한으로 설치한다. 드롭인은 기본 유닛의 계정·리소스·네트워크 제한을 이어받고, 새 확인 디렉터리·서명 저널 디렉터리·캐시만 쓰기 경로로 연다. 새 키 파일과 감사 원본 디렉터리는 읽기 전용이다.
2. 같은 출력의 `metrics_profile` JSON 객체를 exporter가 `--witness-observer-profile`로 읽는 파일에 배치하고 exporter를 재시작한다. exporter가 시작할 때 프로필을 읽으므로 파일 교체만으로 활성 설정이 바뀌지 않는다. 기존 수집기 캐시는 보관한다. 새 프로필은 전환 기록 해시·프로필 해시·최소 영수증이 모두 맞는 새 상태만 사용한다.
3. `systemctl daemon-reload` 후 `systemctl restart secops-audit-witness@INSTANCE.service`를 실행한다. 재시작할 때마다 전환 기록과 두 세대의 연결, 현재 최소 영수증을 확인한다. 검증을 통과하면 같은 새 세대에서 계속 수집한다. 승인 기록이 없거나 일치하지 않으면 수집기가 종료되고, 상태 게시가 가능하면 조회 불가 상태를 쓴다.
4. exporter에서 `secops_witness_status_success = 1`, `secops_witness_last_cycle_success = 1`과 새 세대의 잔여 용량을 확인한다. 전환 중 새 캐시가 없거나 일치하지 않으면 `C01WitnessStatusUnavailable` 규칙이 적용된다. 새 수집이 정상 확인되면 해당 경보와 이전 세대의 용량 경보가 해제된다. 설정 장애에서는 승인 원본과 두 설정을 함께 복구한다.

전환 기록 또는 운영자가 고정한 최소 영수증이 바뀌면 같은 명령으로 설정 두 개를 다시 생성한다. 캐시 경로도 두 해시에 맞춰 바뀐다. 전환 기록 해시는 로컬 상태 확인에 사용되며 Prometheus 메트릭 라벨에는 노출되지 않는다.

테스트는 실제 용량 상수를 유지한 4,096개 서명 fixture, 오래된 감사 원본에 대한 거부, 서로 다른 승인 경합, 첫 서명 응답 유실 후 재시도, 연속 두 번 전환을 다룬다. 4,096개 fixture는 기존 테스트 서명과 미리 적재한 유효 서명을 사용하고, 승인·검증·새 세대 수집은 실제 CLI로 실행한다.

2026-11-20 로컬 검증에서 관련 감사·복원·경보·systemd 계약 테스트는 Windows 154개 통과·10개 제외, Linux 164개 통과였다. 저장소 전체 Ruff 검사도 통과했다. 초기 Linux 실행에서 기존 복원 시험 한 건이 백업의 생성 시각이 미래라는 오류로 실패했으며, 최종 재실행은 시각 검증을 유지한 상태에서 통과했다.

systemd 연결 검증은 `scripts.run_witness_systemd_controls --rollover`를 사용했다. WSL Linux의 실제 systemd에서 임시 유닛과 드롭인으로 21개 조건을 통과했다. 승인 기록이 없을 때와 복구했을 때의 exporter 상태, 연속 재시작 뒤 같은 세대의 수집 증가, 이전 저널·확인 DB와 감사 원본의 바이트 보존을 확인했다. 임시 유닛과 상태도 정리했다. 관련 회귀는 Windows 75개 통과·14개 제외, Linux 89개 통과였다. 기존 및 전환 경보 21개 시나리오는 로컬 `promtool test rules infra/observability/witness-alerts.test.yaml`로 검증했다.
