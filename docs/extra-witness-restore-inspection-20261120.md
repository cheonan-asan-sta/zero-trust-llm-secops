# 복구키 없이 복원본의 보관 지문과 서명 이력 재검증

2026-11-20 · `extra` · 구현 `3d8e52f`. [암호화 백업/복원](extra-witness-control-backup-20261120.md) 후에 키 없이 반복 점검할 경로를 추가했다. [08:00까지의 지속 목표](extra-until-0800-20261120.md)는 진행 중이며 경보 연결과 중단 후보의 명시적 재개 보강을 이어간다.

`inspect_restore`는 승인한 백업/복원 때 별도로 보관한 **package SHA256, restore receipt SHA256, profile SHA256, 최소 영수증 pin**을 모두 요구한다. 해당 암호문과 완료 receipt가 그대로인지 확인하고, 고정 공개키로 현재 확인 DB의 전체 영수증 체인을 검증한다. 백업에 기록한 최소 기준·snapshot head·복원 시 최소 기준·현재 외부 최소 기준이 모두 같은 서명 이력에 존재해야 한다. 초기 snapshot 이후 정상적인 서명 행이 추가된 것은 허용한다. 과거 DB의 byte와 같아야 한다고 요구해 정상 진행을 막지 않는다.

복구키/서명키·원본 감사 DB·witness journal을 읽지 않으며 새 서명을 발행하지 않는다. SQLite 읽기 트랜잭션 하나에서 모든 이력을 확인하고 수집기의 실행 lease를 잡지 않는다. 보관 중인 파일을 수정하거나 원래 복원 시작 시각을 현재 시각으로 갱신하지 않는다. 부분 복원의 `restore.pending`이 있으면 검증도 거부한다.

```bash
python -m scripts.audit_witness_observer_backup inspect-restore --directory <복원-후보> --package <보관-package> --backup-sha256 <외부-package-pin> --restore-receipt-sha256 <외부-완료-receipt-pin> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-최소-pin>
```

이 명령에는 `--key-file`이 없다. 새 receipt pin을 자동 검색해 채택하지 않는다. 지문을 잃은 경우에는 운영자가 별도 승인 근거를 확인해야 한다. 암호문 외부 pin 검증은 AEAD 복호화를 다시 수행한 시험과 다르다. 결과는 `decryption_checked=false`, `live_source_checked=false`, `restore_completion_time_attested=false`, `independent_storage_verified=false`, `automatic_activation_allowed=false`를 명시한다. receipt의 시각은 복원 **시작** 시각이며 실제 완료 시각의 원격 증명이 아니다. 현재 서비스의 정상/접근 허가도 주장하지 않는다.

신규17건은 **Windows17통과·Linux17통과**, 제외0. 앞선 백업/프로세스 관련 묶음은 Windows46통과/4제외·Linux50통과였으며, 이후 읽기 전용 보강과 신규1건을 포함한 inspection17건을 다시 확인했다. 같은 사례를 합산해 새 독립 평가 수로 표시하지 않는다.

원본 DB·서명키·witness journal을 제거한 상태에서도 보관 증명만 검사했고, 암호화 구현을 호출하면 실패하도록 해 복호화를 하지 않는지 확인했다. 실제 collector lease를 다른 연결이 잡은 상태에서도 쓰기/lease 연결 없이 검증했다. 서명 descendant 허용, 외부 최소 기준보다 과거로의 rollback, 다른 패키지/receipt, 부분 복원, 시각/flag/schema 변조, 실제 key 없는 CLI와 오류 비노출을 확인했다. [원본·소스 manifest](infrastructure-results/extra-witness-restore-inspection-20261120.json)에 결과를 보존했다.

기존 모델·정답·임계값 변경0이며 F1 93.41%의 탐지 목표는 여전히 미달이다. 기능 검증을 독립 탐지 성능이나 실제 기업 운영 인수에 합산하지 않는다. 유료/API/AWS/Docker/push/CI/병합/실제8h soak0. 다음은 이 결과의 짧은 TTL 집계와 복원 검증 실패/점검 기한 경보다.
