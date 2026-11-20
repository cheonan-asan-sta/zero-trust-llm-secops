# 검증된 감사 수집기 복원 후보의 운영 전환

이 절차는 완료된 **감사 witness 수집기 제어 DB**를 운영 대상으로 선택한다. 감사 SQLite와 서명 키·저널은 승인된 프로필의 경로에서 사용할 수 있어야 한다. 감사 SQLite를 별도로 복구한 경우 기존 신뢰 기준과 일치하는지 검증하고 운영 경로를 먼저 준비한다. 서명 키와 프로필을 바꾸는 운영은 세대 전환 절차를 따른다. [이전 기록의 별도 보관과 원본 감사 복구](extra-witness-archive.md) · [서명 세대 전환](extra-witness-rollover.md)

## 운영 절차

1. 기존 수집기와 기존 경로에서 실행 중인 수동 수집 명령을 정지한다. 수집기 계정이 소유한 전용 저널 디렉터리를 만든 뒤 최초 한 번 초기화한다.

   ```text
   python -m scripts.audit_witness_activation init --journal ACTIVATION_DB
   ```

2. 운영 기록에 보관한 기존 활성 해시를 `history` 출력과 대조한다. 최초 활성 해시는 0이 64개인 값이다. 계획은 복원 패키지·완료 영수증의 고정 해시, 후보의 서명 계보, 대기 작업 없음, 현재 서명 저널과의 일치, 원본 감사 위치와 서명 키를 검증한다.

   ```text
   python -m scripts.audit_witness_activation history --journal ACTIVATION_DB
   python -m scripts.audit_witness_activation plan --journal ACTIVATION_DB --directory CANDIDATE --package PACKAGE --backup-sha256 BACKUP_PIN --restore-receipt-sha256 RESTORE_PIN --profile-sha256 PROFILE_PIN --minimum-receipt MINIMUM --expected-active-sha256 OLD_ACTIVE
   ```

3. 운영자가 검토한 동일 인수와 계획의 `approval_sha256`을 사용해 승인한다. `OPERATOR`는 기관에서 쓰는 운영자 식별자이며, 명령 실행 권한은 로컬 계정과 파일 권한으로 통제한다.

   ```text
   python -m scripts.audit_witness_activation activate --journal ACTIVATION_DB --directory CANDIDATE --package PACKAGE --backup-sha256 BACKUP_PIN --restore-receipt-sha256 RESTORE_PIN --profile-sha256 PROFILE_PIN --minimum-receipt MINIMUM --expected-active-sha256 OLD_ACTIVE --approval-sha256 APPROVAL --operator OPERATOR
   ```

4. 반환된 `activation_sha256`을 고정한다. 관리 수집기는 이 활성 해시를 사용한다. 수동 확인의 `cycle`은 한 번 수집한다. 기존 수집기 CLI에서 복원 후보를 직접 지정한 `watch`와 `cycle`은 거부된다. 운영자가 보관한 최신 최소 영수증도 함께 지정한다.

   ```text
   python -m scripts.audit_witness_activation watch --journal ACTIVATION_DB --activation-sha256 ACTIVE --minimum-receipt MINIMUM
   ```

5. systemd 설정은 Linux에서 생성한다. 출력의 `systemd_drop_in`을 기존 유닛에 적용하고 같은 출력의 `metrics_profile`을 exporter에 설치한다. exporter 재시작, `systemctl daemon-reload`, 수집기 재시작 순서로 적용한다. 관리 저널의 상위 폴더에는 SQLite 쓰기 권한이 열리므로 전용 폴더를 사용한다. 공개 상태는 활성 해시와 최소 영수증에 묶인다. [드롭인과 exporter 적용 순서](extra-witness-rollover.md#systemd와-경보-전환)

   ```text
   python -m scripts.audit_witness_activation systemd-config --journal ACTIVATION_DB --activation-sha256 ACTIVE --minimum-receipt MINIMUM --status-directory STATUS_DIRECTORY
   ```

## 이력과 재시도

- 저널은 제출·승인·활성화·거부를 시각, 운영자 라벨, 시도 ID와 함께 저장한다. 관리 수집기의 시작·수집 실패도 기록한다. 각 행에 이전 이벤트 해시가 포함된다. `history --expected-head-sha256 PIN`으로 별도 보관한 지문이 이력에 남았는지 확인한다.
- 승인과 선택 변경은 하나의 SQLite 트랜잭션으로 기록한다. 후보나 현재 서명 저널이 바뀌면 거부한다. 제출 후 중단되면 제출 행만 남을 수 있다. 활성 해시와 시도 결과를 조회한 뒤 다시 검토한다.
- 전환 뒤 시작이 실패하면 선택을 유지하고 실패를 기록한다. 현재 서명 이력을 만족하는 후보를 새로 검토하거나 실패 원인을 해결한다. 같은 관리 저널을 쓰는 기존 수집기는 서명 주기마다 선택을 확인하므로 이전 활성 해시로 수집을 이어갈 수 없다. 기존 경로를 직접 구동하는 수집기는 첫 전환 전에 정지한다.
- 저널은 최대 10,000행이다. 저널과 외부 지문은 별도로 보관한다. 동일 호스트 관리자가 파일과 외부 지문을 모두 통제하는 상황에는 독립 보관이 필요하다.

## 무료 로컬 검증

전환 전용 테스트는 승인 전 CLI 수집 거부, 승인 후 재시작 수집, 서명 저널보다 오래된 후보와 손상된 영수증·누락 키 거부, 이전 활성 해시 사용 차단, 전환 저장 실패 때의 트랜잭션 롤백, 수집과 전환 검증의 경합을 확인한다.

전환 전용 8개를 포함한 최종 회귀는 Windows 96개 통과·8개 제외, Linux 104개 통과였다. 저장소 전체 Ruff 검사도 통과했다.

WSL Linux의 실제 systemd에서 `scripts.run_witness_systemd_controls --activation`으로 19개 조건을 통과했다. 잘못된 승인은 선택을 만들지 않았고, 승인된 복원 후보는 두 번의 실제 유닛 시작에서 수집을 이어갔다. 이전 제어 DB와 감사 원본을 대조했고 승인·전환·거부 이력 및 임시 자원 정리를 확인했다. 첫 시험은 임시 복원 부모의 권한이 너무 넓어 기존 권한 검사에서 중단됐다. 임시 부모를 비공개로 준비해 재실행했다.
