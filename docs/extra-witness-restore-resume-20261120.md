# 중단된 복원 후보를 같은 근거로 명시적 재개

2026-11-20 · `extra` · 구현 `b276924`. [암호화 백업/복원](extra-witness-control-backup-20261120.md)의 새 디렉터리 재복원 경로에 더해, 완료되지 않은 후보의 정확한 재개를 추가했다. [08:00까지의 지속 목표](extra-until-0800-20261120.md)는 계속 진행 중이다.

## 재개의 범위

기존 `restore`는 여전히 새 디렉터리만 허용한다. 별도 `resume-restore` 명령은 원래 package/key/profile/최소 영수증 pin으로만 중단 후보를 이어간다. AEAD와 snapshot 전체를 다시 검증하고, `restore.pending`의 범위·시작 시각·파일 목록을 확인한다. 이미 있는 프로필/공개키/확인 DB는 원래 bytes와 같아야 하고 없는 파일만 만든다. 잘린 파일·다른 내용·symlink/hardlink/위험 모드·알 수 없는 파일은 삭제/덮어쓰기로 복구하지 않는다. 이 경우 기존 새 후보 복원을 사용할 수 있다.

완료 단계는 SQLite lease로 직렬화한다. 원래 marker가 바뀌지 않았는지 다시 확인하고 현재 복원 상태와 snapshot을 비교한다. 완료 receipt가 이미 있다면 원래 내용과 정확히 같아야 한다. 기존 시작 시각을 유지해 receipt를 마무리한 뒤에만 marker를 제거한다. 중간에 다시 종료돼도 동일한 완성 파일 prefix는 재개할 수 있다. byte 일부만 기록된 파일이나 부분 receipt는 그대로 거부하며 임의의 모든 중단이 자동으로 고쳐진다고 주장하지 않는다.

이미 완료돼 marker가 없는 후보는 재개하지 않는다. 보관한 완료 receipt pin으로 [별도 검증](extra-witness-restore-inspection-20261120.md)을 사용한다. 새 기준·다른 package를 자동 채택하거나 완료된 복원 시작 시각을 새로 갱신하지 않는다. 복원/재개는 후보 작성이며 앱 설정·운영 서비스·신원·접근 권한을 바꾸지 않는다.

```bash
python -m scripts.audit_witness_observer_backup resume-restore --package <원래-package> --backup-sha256 <원래-package-pin> --profile-sha256 <원래-profile-pin> --minimum-receipt <원래-외부-최소-pin> --destination <중단된-후보> --key-file <분리한-원래-key> --key-sha256 <원래-key-pin>
```

## 실제 로컬 검증

확대 묶음 **Windows255통과·23제외, Linux278통과·제외0**. 신규 재개22건은 Windows18통과/4 POSIX 제외·Linux22통과다. 다른 제외는 기존 POSIX 권한/공개 게시 경로다. 기존 witness·clock·수집기·암호화 백업·중단 복원·키 없는 검증·상태 집계/exporter·checkpoint/progression까지 묶었다. 전체 프로젝트 회귀 또는 독립 탐지 사례로 합산하지 않는다.

실제 프로세스를 marker/파일/receipt 저장 직후 종료91/92/93으로 중단하고 새 CLI 프로세스로 정확히 재개했다. 재개 중에도 프로필/receipt 저장 뒤 종료98/99를 주입해 다시 이어갔다. 원본 감사/원본 확인 기록/witness journal의 bytes와 원래 시작 시각·기존 완성 파일·receipt를 유지했다. 잘린 파일·다른 프로필·다른 package·더 약한 최소 기준·다른 key·미래/과거 marker·부정확한 receipt·활성 lease·동시 재개·unsafe POSIX 파일을 거부했다. 동시 재개는 완료1회이며 완료된 후보의 재개 반복은 거부한다.

시각 경계와 복원 변경 후 기존 실제 Prometheus/Alertmanager 흐름도 **18조건·장애4회** 다시 통과했다. 발생과 동일 episode 해제·원인 metric·원본 보존을 확인했다. 앞 버전의 동일 시나리오를 더해 새로운 독립 사례 수로 표시하지 않는다. 모든 실험 프로세스/서버/임시 키·DB는 정리했다. Windows는 기능/상태 시험이며 POSIX/Windows ACL 운영 인수를 뜻하지 않는다.

[소스·원본 manifest](infrastructure-results/extra-witness-restore-resume-20261120.json)를 보존했다. 기존 LLM F1 93.41%·재현율90.56%는 그대로이며 탐지 목표는 미달이다. 모델/정답/분모 변경0, 새 유료/API/AWS/Docker/push/CI/병합/실제8h soak0. 다음은 응답 유실·원본/확인 기록 rollback·백업 handoff·복원 재개가 여러 순서로 섞여도 외부 최소 기준이 유지되는 순서 시험이다.
