# 실제 HTTP worker 재기동 후 감사 커서 재개

2026-11-19 · extra · 무료 로컬 인수. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 새로 검증한 경계

앞선 페이지 시험의 별도 프로세스는 direct reader였다. 이번에는 정상 앱의 인증·PDP·공유 참조·SQLite 감사·cursor factory를 여는 실제 HTTP 프로세스3개를 순서대로 시작했다. 준비 token·실제 PID를 parent가 소유한 handle과 대조하고, `kill()`/`wait()`로 강제 종료를 확인한다. 다른 앱 PID를 검색해 종료하지 않는다.

첫 worker가 실제 native 실행 근거를 분석해 감사1행을 커밋한 뒤 종료된다. 두 번째는 같은 감사 DB/공유 참조를 다시 검증해 두 번째 분석을 저장하고, 원래 proof 만료 전에 참조 철회가 모델 호출 없이404가 되는지 확인한다.

그 뒤 `review_status=PENDING, limit=1` 페이지 커서를 만든다. 최신 분석을 RESOLVED로 검토해 감사3행(분석2개+검토1개)이 된 후 두 번째 worker도 강제 종료한다. 세 번째는 같은 전용 private 키/pin으로 원래 커서를 복호화해 두 번째 페이지를 TCP HTTP로 반환한다. snapshot ID·필터·생성/만료 시각을 유지하고, 원래 PENDING view의2개 분석을 기준으로 이어 읽는다. 새 페이지를 시작하면 현재 PENDING은1개이고 최신 상세 조회는 RESOLVED다.

과거 view와 현재 검토 상태를 분리하는 시험이다. 검토 완료가 권한 발급/소비한 grant 재발급을 뜻하지 않으며, source 앱 권한 journal과 실행 evidence DB는 그대로다. 세 번째 worker의 provider stub 호출은0회다. 첫 두 worker는 각1회 stub이며 유료 호출은0이다.

## 현재 cursor 키와 readiness

현재 key 파일을 다른32바이트로 교체해 기존 pin과 어긋나게 만들면 page는503이다. 메모리에 있던 이전 키나 새 임의 키로 우회하지 않는다. `/health/ready`에도 `audit_paging.ok=false`를 넣고503을 반환하며 `/health/live`는200이다. 이 readiness 공백은 변경 전1개 실패로 재현했다.

readiness가 반환하는 cursor 정보는 `ok`, key mode와 TTL뿐이다. key 값·경로·pin·cursor를 반환하지 않는다. 설정된 key의 잘못된 pin은 HTTP를 수신하기 전 startup 실패이며 retry/fallback은 없다. 시험 소유 전용 key는 모든 worker가 종료된 뒤 제거했다.

## 검증 프로세스의 설정 격리

테스트 worker는 parent의 모든 앱 Settings 환경변수를 제거하고 고정 control 값만 제공한다. 모듈 경로는 명시적으로 유지하고, 작업 디렉터리는 자신이 소유한 private 폴더다. 그 폴더에 `.env.local`가 있으면 실행을 거부한다. 프로젝트/사용자의 실제 dotenv나 상속된 DB/key 경로를 읽어 다른 저장소를 초기화하지 않는다.

독립 시험은 parent에 잘못된 cursor key 경로와 다른 behavior DB 경로를 넣어도 해당 파일을 읽거나 만들지 않는 것을 확인했다. 정상 앱의 factory는 그대로 사용하며 provider만 명시적 테스트 stub이다. 생산 launch mode를 바꾼 것이 아니다.

## 결과와 재현

신규5개를 포함해 Windows 관련159건/제외2건·Linux 확대244건/제외2건 통과. 제외2건은 기존 SQLite에 적용하지 않는 JSONL view 변경 사례다. OS별 겹치는 사례를 합산하지 않는다.

실제 root/systemd/ptrace·로컬 OIDC/서명·독립 reader·공유 참조·HTTP worker·감사 암호화 백업/복원에 새6조건을 더한 **47조건 통과**. 세 실제 worker의 Linux exit code는 모두-9다. 소유 process/unit/private 상태/임시 의존성과 cursor key가 정리됐고 원래 앱 권한/실행 evidence·원래 감사 DB 보존도 확인했다. [검증·소스 지문](infrastructure-results/extra-http-cursor-recovery-20261119.json), [실제 run 결과](infrastructure-results/extra-http-cursor-recovery-20261119-systemd.json).

```sh
python -m pytest tests/test_http_worker_restart.py tests/test_audit_paging_http.py tests/test_audit_paging.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

두 번째는 기존 root/systemd/의존성이 준비된 로컬 Linux 인수다. `--worker-paging`은 worker restart·공유 참조·HTTP·LLM 근거 stub·감사 백업/복원을 포함한다. 기존 `--worker-restart`의2-worker/6조건 동작은 유지한다.

127.0.0.1의 TCP HTTP와 실제 API 키를 사용했다. 이 결과는 mTLS 구간·원격망 단절·실제 사람 SSO·호스트 전원 단절/재부팅·다중 호스트·원격 WORM이나 연기한8시간 시험의 증명이 아니다. LLM 탐지 성능을 새로 측정하지 않았고 평가 원본/정답/예측/F1·오탐/미탐은 바꾸지 않았다. 후속으로 [checkpoint 파일 보관·외부 pin 복원 연결과49조건 인수](extra-audit-checkpoint-20261119.md)를 추가했다. 위47조건은 이 HTTP cursor 작업 당시 기록이다.
