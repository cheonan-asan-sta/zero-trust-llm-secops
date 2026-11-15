# PAM 관측 체크포인트·암호화 사본·격리 복원

이 기능은 이미 수집해 검증한 PAM 관측을 중복 없이 보존하고, 사본 손상·분실·되돌림을 확인하기 위한 인프라 기능이다. 위협 탐지 모델·임계값·과거 라벨을 바꾸지 않는다. 과거 관측의 보존 확인을 실제 사람 인증·현재 신선도·권한 부여·정상 판정으로 바꾸지 않는다.

## 구현

`PamObservationLedger.checkpoint()`는 기존 inventory 검증과 같은 SQLite writer fence 안에서 논리 출처/저장 한도, 수집 순서, 원래 시각, capture·사건 지문, 중복 집계, 최신 metadata를 길이 구분한 SHA256에 묶는다. 사건 수가 같은 다른 유효 DB도 다른 지문이다. `scripts.checkpoint_pam_observations`의 `--expected-sha256`로 운영자가 별도로 보관한 지문과 대조한다. 키 ID 교체는 논리 출처를 초기화하지 않는다. 선택한 key-id는 과거 저장소의 scope를 구성할 뿐 현재 키 권한을 승인하지 않는다.

`PamObservationBackup`은 그 외부 관측 지문을 필수 입력으로 받아 SQLite transaction의 일관된 사본을 검증한다. 기존 capture/exec 복구에서 쓰던 비공개 파일·fresh 출력·AES-256-GCM 패턴을 재사용하고 PAM 전용 schema를 둔다. 원래 실행 근거 archive로 위장한 PAM event를 넣지 않는다. 별도 복구 키는32바이트 메모리 입력이며 파일/argv/환경변수·공개 보고서에 기록하지 않는다. 매 사본에 새12바이트 nonce를 사용하고 논리 설정·원래 관측 지문·DB 지문·시각·key-id를 AAD에 묶는다. 암호문/manifest/checkpoint를 각각 외부 SHA로 대조한다.

복원은 모든 pin·schema·AES 인증·DB 바이트·논리 inventory를 확인한 뒤 원래 소스와 겹치지 않는 새0700 검토 디렉터리에 `review.sqlite3`와0600 영수증을 만든다. 같은 출력·기존 checkpoint를 덮어쓰지 않는다. 원래 source 경로·서비스·수집기·grant를 만들거나 활성화하지 않는다. 임시 평문 검증 사본은 owner-only 디렉터리에서 확인한 뒤 제거한다. 로컬 파일 시스템·소유자·시계·관리자와 복구 키 보관자는 신뢰 경계다.

`check_review()`와 `status()`는 복구/서명 키 없이 암호문·manifest·검토 DB·영수증·관측 지문을 다시 대조한다. 성공 영수증도 별도 SHA가 필요하다. 손상/누락/알 수 없는 파일/잘못된 소유권·권한·링크/경로 겹침이면 `unavailable`, 건수는 null이다. 이전 성공 건수를 정상처럼 재사용하지 않는다. 정확한 원래 바이트를 되돌린 뒤에도 원래 관측·복원 시각은 바뀌지 않는다.

## 사용 경계

관측 checkpoint SHA, 암호화 package checkpoint SHA, 복원 영수증 SHA는 서로 다른 지문이다. 운영자가 신뢰한 입수/보관 경로에서 별도로 전달해야 한다. DB와 pin을 같은 관리자에게 함께 되돌릴 수 있게 보관하면 rollback 보호가 되지 않는다. 원격 append-only witness·독립 승인·키 관리·물리 다중 호스트 또는 원격 저장소 재난 복구를 완료했다고 주장하지 않는다. 새 admission 뒤에는 명시적으로 최신 pin을 다시 확보해야 한다. 오래된 사본을 현재 자료로 자동 승격하지 않는다.

현재 backup/restore는 인프라 Python API이며 키를 받는 운영 CLI·credential 설치·보관 만료 삭제·외부 경보 라우팅의 전 과정은 별도 인수다. `status()`는 연동할 수 있는 집계 결과를 제공한다. 이번 시험은 source loss→restore와 손상→unavailable→원래 바이트 재검증을 로컬에서 확인하며, 실제 운영 경보 발송·업무 계정 설치 완료를 뜻하지 않는다.

## 검증과 재현

최종 소스·전체/집중 결과·실제 systemd·별도 Docker 제어 결과와 실패/정리는 공개 JSON에 연결한다. 집중 시험은 전체의 부분집합이며 반복 실행 수를 합산하지 않는다. Docker 복구 시험의 PAM 관측은 합성 기능 fixture다. 실제 sudo/journal 출처와 키 없는 daemon·checkpoint 검증23조건은 별도 systemd 시험으로 확인한다. 합성 backup fixture를 실제 사람 인증이나 새 독립 위협 평가로 집계하지 않는다.

기존1,681,815행 판정/FP/FN 비교를 유지하며 모델/임계값/라벨 변경은 없다. 목표 수치는 여전히 미달이다. AWS/유료 API0이며 사용자가 미룬8/12시간 soak를 시작하지 않는다.

최종 고정 소스 `4d39325c2a58d4ba61cf445c17d859118f93038e362a0238c5f1eaa8ace3c46a`에서 전체6,380·집중158건(전체의 부분집합)을 통과했다. v97 이후 신규48건이다. 실제 systemd67/10/23조건과 별도 Docker6조건을 같은 소스로 확인했고 소유 자원을 정리했다. 기존1,681,815행 판정 지문은 같으며 새FP0·기존TP 손실0이다. [세부 결과·지문·실패 이력](infrastructure-results/extra-pam-observation-recovery-v99-20261116.json).

```bash
python3 scripts/run_pam_recovery_docker_controls.py \
  --source-archive /absolute/path/source.tar \
  --source-sha256 4d39325c2a58d4ba61cf445c17d859118f93038e362a0238c5f1eaa8ace3c46a \
  --image-id sha256:APPROVED_CACHED_PYTHON312_TEST_IMAGE \
  --output /absolute/path/fresh-pam-docker-results
```

재현용 검증 실행기는 frozen source.tar 밖에서 별도로 제공한다. 로컬 Unix/npipe Docker endpoint와 Linux 엔진·정확한 cached image ID만 허용하며 이미지 pull/패키지 설치·remote daemon 연결을 하지 않는다. 해당 image에는 승인된 test.lock 의존성이 있어야 한다. initializer만 소유 volume에 CHOWN capability를 쓰고, writer/reader는 UID10001·cap0·NNP·networknone으로 분리한다. reader의 volume은 읽기 전용이다. Python -O 상태에서도 호스트 사전조건/소유권 확인이 유지되며 자식 Python은 -I로 실행한다. 반복 실행 수를 독립 성능 표본이나 통과 건수에 합산하지 않는다.
