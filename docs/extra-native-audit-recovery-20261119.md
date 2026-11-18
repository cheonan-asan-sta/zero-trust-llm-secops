# 실제 native 실행과 공동 감사 백업·복원 통합 인수

2026-11-19 · extra · 오전08:00 목표의 후속 검증. 로컬 systemd/SQLite/127.0.0.1 TCP를 사용했다. 유료 API·AWS·push·CI·병합·운영 설정 전환은 하지 않았다.

## 연결된 흐름

1. 실제 systemd unit에서 ptrace가 첫 성공 exec를 관측한다.
2. 로컬 OIDC fixture의 호출자 영수증, 서명된 실행/인가 근거와 실제 앱 grant 소비를 연결한다.
3. 암호화 공유 참조를 새 reader 프로세스가 복원하고 현재 출처/정책/세션으로 재검증한다.
4. 실제 TCP HTTP 요청과 API 키 인증을 거쳐 기존 OpenAI grounded 어댑터에 근거를 전달한다. provider 응답 경계만 명시적인 stub이다.
5. SQLite 공동 감사 writer가 정책 가드 적용 결과와 원래 검증 문맥을 기록한다.
6. 온라인 snapshot을 암호화해 백업하고 패키지/DB/head 핀을 검증해 새 경로에 복원한다.
7. **테스트 harness가 명시적으로** 복원 후보를 임시 HTTP 감사 backend로 선택해 조회·검토 CAS를 시험한다. 일반 restore 함수가 backend를 활성화하는 것은 아니다.

## 결과

- 실제 systemd 통합 인수 **35조건 통과**. 이전 공유/HTTP29조건에 audit recovery6조건이 포함됐다.
- Linux 관련 회귀 **197건 통과**, Windows HTTP 관련 **49건 통과**. 같은 논리 시험과 native 인수 조건을 합쳐 성능 평가 사례 수로 보고하지 않는다.
- HTTP 응답과 재로딩한 원본 SQLite 감사 기록이 일치했다. 복원 후보에서도 동일한 assessment, native 증거·참조 해시, 정책 가드가 유지됐다.
- 복원 후보를 검토하면 후보의 seq가1→2로 증가했고 원본 DB는 seq1의 바이트 그대로 보존됐다.
- 후보의 최신 검토 head를 기준으로 이전의 정상 암호화 백업을 복원하려 하면 거부됐다. tag 변조 패키지도 거부되며 실패한 출력 경로는 생성되지 않았다.
- HTTP 분석의 provider stub 호출은1회였다. 복원 후보 조회·검토는 추가 모델 호출을 하지 않았다. 앞선 내부 입력 검증의 stub 호출은 별도다. 실제 유료 provider 호출은0회다.
- 앱 권한 journal·실행 근거 DB는 바뀌지 않았다. 복구 과정에서 새 grant를 발급하지 않는다. 새 자원 접근 요청이나 만료된 권한의 재사용 성공을 시험했다고 주장하지 않는다.
- 생성한 UUID unit, private 상태/테스트 키/패키지/후보 DB, TCP 서버와 `/run` 임시 의존성을 정리했다. 보관하는 결과에는 원문 키·JWT·서명·nonce·실행 참조를 넣지 않았다.

[검증 요약·소스 지문](infrastructure-results/extra-native-audit-recovery-20261119.json), [실제 native 인수 run.json](infrastructure-results/extra-native-audit-recovery-20261119-systemd.json).

## 재현

```sh
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --audit-recovery
python -m pytest tests/test_native_analysis_http.py tests/test_shared_native_analysis.py tests/test_audit_transfer.py tests/test_sqlite_audit.py tests/test_federated_audit.py tests/test_audit.py tests/test_audit_cancellation.py tests/test_audit_preflight.py tests/test_api.py tests/test_verified_caller_authority.py -q
```

첫 명령은 Linux root·systemd PID1·기존 collector 의존성 환경용이다. `--audit-recovery`는 공유 참조/HTTP/내부 LLM 입력 시험을 포함하고 HTTP 감사 writer를 이 harness 안에서 SQLite로 선택한다. 기본 앱 backend는 변경하지 않는다. 실제 모델 평가나 기업 SSO 시험이 아니다.

초기 unit 인수에서 복원 후보 조회 전에 HTTP client context가 이미 닫힌 문제를 발견했다. 후속 단계용 로컬 client를 별도로 열어 수정하고 다시 검증했다. 결과는 수정 후 통과를 기준으로 기록한다.

## 다음 검증 범위

HTTP worker 프로세스 자체의 강제 종료·새 프로세스 재기동, 취소/부하와 대규모 조회 비용 개선을 이어간다. 이번 HTTP 서버는 harness의 별도 thread로 실행하고 정상 종료했다. 독립 reader 프로세스 재기동 및 이전 SQLite writer의 commit 전후 강제 종료 시험과 HTTP 서버 프로세스 강제 종료를 동일한 시험으로 설명하지 않는다. 실제 호스트 재부팅/전원 단절/네트워크 파일시스템 내구성은 아직 검증하지 않았다.

실제 사람의 SSO/MFA, 전체/PAM 감사, 독립 탐지 성능 목표, 원격 WORM은 별도다. 기존 개발 평가 F1 93.41%를 새로 개선한 결과로 계산하지 않으며 8시간 연속 시험도 자동 시작하지 않았다.
