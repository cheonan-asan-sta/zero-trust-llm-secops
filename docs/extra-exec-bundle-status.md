# 실행 복구 묶음의 키 없는 재검증과 경보

**최신 판정 — 2026-11-16:** [현재 구현·검증·남은 작업](infrastructure-current-state-20261116.md). 고정 로컬 전체6,332·집중475개와 실제 systemd/DB 인수 결과를 연결했다. 탐지 독립 목표는 미달·장기 soak는 유예다. 아래의 이전 날짜 수치/상태는 작성 당시 누적 기록이며 최신 판정은 연결한 문서를 따른다.

## 관측 범위

`zt-exec-recovery-bundle-status-1`은 v89의 암호화 묶음 **현재 바이트와 이미 격리 복원한 사본**을 함께 재검증한다. 외부 checkpoint·manifest·payload SHA와 외부 receipt pin, 복원 파일 inventory, 원래 스냅샷 SHA, 현재 서비스/호출자 공개 신뢰와 앱/브로커 결합을 다시 검사한다. 복구 키로 새로 복호화하거나 checkpoint/receipt를 자동 갱신하지 않는다. 최초 GCM 복호화와 검증을 완료한 신뢰된 복원 절차가 발급한 receipt를 근거로 한다.

`verified`는 이 자료의 무결성과 상호 결합이 검증됐다는 뜻이다. 원본에 seal이 없는 실행1건은 백업·복원·재검증 후에도 `indeterminate=1`이다. 실제 사람의 현재 접속 인증, grant 활성화, 실행 허가, 운영 서비스 복구 완료를 뜻하지 않는다. 세 가지 자동 활성화/실행/인가 플래그는 항상 false다.

복원 검증의 시작 시각뿐 아니라 **검증 완료 시점의 현재 신뢰**도 다시 검사한다. 처리 도중 키/신뢰 유효기간이 끝나면 성공 보고서를 내지 않는다. 명시적인 제어 시각을 받는 단위 시험과 실제 시계 기반 운영 경로를 구분한다.

## 구현·운영 입력

- `scripts/f1_lab/exec_bundle_status.py`: 암호화 패키지와 격리 review를 키 없이 대조하고 원래 snapshot/backup/restore 시각과 한도 있는 집계를 반환한다. 손상·pin 불일치·현재 신뢰 실패 시 unavailable이며 예전 카운터를 넣지 않는다.
- `python -m scripts.exec_bundle_status`: 범위, 공개 registry/caller-registry와 SHA, package/review 경로, checkpoint/receipt SHA, `--status-output`을 받는다. 키·launch·activate 입력은 없다. 기본 oidc, 로컬 시험만 `--caller-environment local_oidc`를 명시한다. 공개 출력은 증거/외부 pin 디렉터리와 겹치면 거부한다.
- `scripts/signal_metrics_exporter.py --exec-bundle-profile ...`: 선택형 `secops_exec_bundle_*` 집계. 인증된 metrics 엔드포인트에서만 제공하며 설정을 생략한 기존 배포에는 새 집계/경보가 없다. profile에는 scope SHA, 절대 status 경로, snapshot/restore 최대 나이(초)를 명시한다.
- `infra/systemd/secops-exec-bundle-status@.service/.timer`: opt-in 템플릿.0700/0600으로 사전 배치한 checker 소유 사본과 공개 신뢰/외부 pin을 읽고 공개 CacheDirectory만 쓴다. 개인키·복구 키·토큰·live DB·원래 worker 경로는 제공하지 않는다. 이 검사에는 증거 잠금 파일에 대한 쓰기 권한도 필요하지 않다. 자동 설치·enable은 없다.

공개 status TTL은60초다. 미래/만료/잘못된 보고서는 실패 처리하며 이전 카운터를 재사용하지 않는다. 재검증은 `checked_at`만 갱신할 수 있고 snapshot/backup/restore 최초 시각은 그대로다. 오래된 복원본을 자주 검사해 복구 시험이 최근에 끝난 것처럼 만들 수 없다.

| 경보 | 등급 | 의미 |
|---|---|---|
| C01ExecBundleVerificationUnavailable | critical | 자료·현재 신뢰·공개 보고서의 검증 불가 |
| C01ExecBundleRecoveryOverdue | warning | 원래 snapshot/restore가 설정된 나이를 초과 |
| C01ExecBundleIndeterminateRetained | warning | 검증된 사본에도 완전한 seal이 없는 요청이 남음 |

unavailable 동안 개별 집계 경보가 해제되는 것은 상태가 해결돼서가 아니라 관측 값이 없어서다. critical 검증 불가 경보가 이를 대체한다. 정상 복원이나 경보 억제와 혼동하지 않는다.

## 로컬 검증 계획과 현재 상태

단위 시험은 실제 서명된 fixture와 실제 암호화/격리 복원 사본으로 패키지·DB·seal·pin 손상, 정확한 수리, 최초 시각 유지, TTL/미래 시각, schema/profile, exporter 인증과 기본 opt-out, CLI, 검증 중 키 만료를 확인한다. 첫 집중 시험의148개는 통과했고 profile 부정 입력6개는 테스트용 빈 scope 때문에 원하는 검증에 도달하지 못해 실패했다. 실제 ArchiveScope로 고치고 유효 profile의 성공도 먼저 확인하도록 했다. 제품 scope 검사를 낮추지 않는다.

실제 systemd 검증에서는 v89의 보호 명령 exec6회와 선택 원본 유실/격리 복원을 재사용한다. 별도 PID1 시작 `nobody` 프로세스에 package/review/checkpoint **소유 사본과 공개 신뢰만** 전달한다. capability0/NoNewPrivileges와 실제 payload·review DB·checkpoint 쓰기 거절을 검사한다. Python facade의 키 없는 인터페이스 검사를 넘어 별도 OS 프로세스가 실행되지만, 실제 운영 원본의 소유권/ACL 전환 완료는 아니다.

그 실행에서 만든 실제 공개 보고서 verified → ciphertext bitflip으로 unavailable → 같은 바이트 수리 후 verified를 실제 Prometheus/Alertmanager에 전달한다. unknown1과 최초 시각은 보존해야 한다. 실제30초 경과로 snapshot 나이 경보, 명시적인 나이 정책 변경에 따른 해제(새 snapshot/restore가 아님), 실제60초 경과 보고서 만료도 확인한다. 로컬 파일 브리지 검증이며 운영 다중 호스트 mTLS·물리 외부 저장소 재난 복구 인수를 대신하지 않는다.

최종 고정 소스·집중/전체/실제 경보 결과는 완료 후 추가한다. 기존 탐지 모델·정답·임계값과 분리하며 운영 경보 조건 수를 F1 표본에 합산하지 않는다. AWS/유료 API0, 사용자 유예한8시간/12시간 soak는 실행하지 않는다.


## 최신 통합 인수 — 2026-11-16

부모의 보관 잠금 경합 수정까지 포함한 고정 소스 `36122c3f796fc28f63ab4bcd9bfbd98c65db1d999d33e16c7fbc4733652b1418`에서 집중542개·전체6,070개·실제systemd67조건·실제Prometheus/Alertmanager9조건을 통과했다. 신규35개이며 실패/skip0이다. 집중은 전체의 부분집합이고, 이전524/6,052 결과를 합산하지 않는다. 원래 qualification commit은 `b813dd9`이며 게시 전 코드/설정 지문 동일성을 확인했다. 부모 PR83은 수정 head의 CI17개 성공 후 aitest `b31f3b5`에 병합됐다.

별도 PID1 nobody worker는 UID65534·effective/bounding capability0·NNP이며 복구키와 서명키를 받지 않았다. 실제 payload·review DB·checkpoint 쓰기가 거절됐다. 손상한 ciphertext에서 unavailable, 정확한 바이트 수리 후 verified로 돌아와도 원래 시각과 확인불가1건은 그대로다. 실제30초 나이 경보와60초 보고서 만료, 정책 변경에 의한 경보 해제를 구분했다. 소유 사본 기반 시험이며 운영 원본 ACL 전환·물리 외부 저장소 인수가 완료됐다는 의미는 아니다.

기존1,681,815행 판정 지문은 동일하고 새 FP/기존 TP 손실/정답 재열람은0이다. 공유 감사F1 0%·웹 감사80.70%·인증95.08%와 각각의 재현율 미달은 유지한다. 이 운영 통제 수를 탐지 F1 표본에 합산하지 않는다. 소유 컨테이너·unit·상태·소스·관측 프로세스를 정리했다. AWS/유료 API0, 장기 soak유예다. [집계·코드 지문·실행 원본 근거](infrastructure-results/extra-exec-bundle-status-v90-20261116.json).
