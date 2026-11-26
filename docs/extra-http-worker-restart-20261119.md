# 실제 HTTP worker 프로세스 강제 종료·재기동 인수

2026-11-19 · extra · 오전08:00 목표의 후속. 로컬 실행만 수행했고 유료 API/AWS/push/CI/병합은 하지 않았다.

## 새로 확인한 경계

이전 인수의 HTTP 서버는 thread였다. 이번에는 정상 앱의 설정·PDP·공유 참조·SQLite 감사 factory를 로드하는 **별도 Python 프로세스** 두 개를 순서대로 시작했다. `scripts.native_http_worker`는 명시적인 테스트 전용 entrypoint이며 provider 응답만 stub으로 대체한다. 실제 조직 서비스의 시작 설정을 바꾸지 않는다.

각 프로세스는 127.0.0.1의 자동 선택 포트에만 bind한다. 준비 파일에는 무작위 control token, 실제 interpreter PID, port와 stub 표시를 쓴다. parent는 token/PID를 자신이 생성한 `Popen` handle과 대조하고 liveness 요청으로 실제 수신을 확인한다. 준비 실패/시간 초과를 자동 재시작하지 않으며 자신의 테스트 프로세스를 종료하고 실패로 기록한다.

첫 worker에서 실제 API 키 인증·엄격한 참조 요청 형식과 native 분석을 확인한 뒤 **실제 worker PID를 강제 종료**한다. 새 worker가 같은 DB를 다시 열어 첫 응답과 동일한 감사 기록을 반환하고, 같은 공유 실행 참조를 현재 근거로 다시 검증한다. 이후 다른 프로세스에서 참조를 철회하면 새 worker는 모델 호출 없이404로 거부한다. 이 철회 확인은 원래 근거 만료 전에 완료됐는지도 검사해 만료와 혼동하지 않는다.

두 분석 모두 이미 소비된 grant에 대해 HOLD/사람 검토를 유지한다. 감사 기록은 두 개의 별도 analysis이며 원래 앱 권한 journal·실행 근거 DB는 변하지 않았다. 프로세스 재시작이 grant를 발급하거나 서비스를 재실행하지 않는다.

## Windows PID 보완

초기 시험에서 Windows venv 실행기의 `Popen.pid`와 실제 interpreter PID가 다름을 재현했다. 잘못된 PID를 실제 서버라고 인정하지 않고 readiness binding을 실패시켰다. Windows에서는 실제 base interpreter를 직접 실행하고 부모의 모듈 검색 경로를 전달하도록 수정했다. Linux는 기존 venv interpreter 경로를 사용한다.

이 helper를 기존 SQLite commit 전후 강제 종료 시험에도 적용하고 child가 직접 출력한 PID와 handle PID가 같은지 검증했다. 강제 종료 성공은 정상 종료가 아닌 exit code와 `wait()` 결과로 확인한다. 재시작한 서버와 source DB 검증은 별도다. 다른 사용자 프로세스나 기존 앱 PID를 검색해서 종료하지 않는다.

## 결과

- 실제 systemd/ptrace·독립 reader·TCP HTTP·감사 복원에 worker 종료/재기동을 더한 **41조건 통과**. 앞선35조건에 새6조건이 포함된다.
- Linux 관련 확대 회귀 **199건 통과**. 철회/만료 구분 보완 후 최신 Windows/Linux 집중 시험은 각각22건 통과(새 worker2건+기존 SQLite20건)다. 겹치는 사례 수를 합산하지 않는다.
- 실제 native 실행 인수의 두 worker exit code는 각각-9로 강제 종료가 확인됐다. SQLite 감사 verified row는2개이고 worker별 provider stub은1회씩이다. parent HTTP/내부 검증의 stub 호출과 별도이며 유료 API 횟수는0이다.
- 잘못된 bootstrap pin은 worker가 HTTP를 수신하기 전에 실패했다. retry나 메모리 backend fallback은 없다.
- 생성한 worker·loopback 서버·systemd unit·private 상태·임시 의존성을 정리했다. 원래 프로젝트 자료·다른 앱·기존 Docker daemon은 중단하지 않았다.

[검증 요약·소스 지문](infrastructure-results/extra-http-worker-restart-20261119.json), [실제 native run 결과](infrastructure-results/extra-http-worker-restart-20261119-systemd.json).

```sh
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-restart
python -m pytest tests/test_http_worker_restart.py tests/test_sqlite_audit.py -q
```

첫 명령은 기존 root/systemd/Python 의존성을 갖춘 로컬 Linux 인수용이다. `--worker-restart`는 공유 참조·HTTP·감사 백업 복원 검증을 포함한다. provider는 stub이며 이 결과는 모델의 탐지 품질이나 실사용 사람 SSO의 검증이 아니다.

## 이어갈 범위

HTTP 취소/대기/부하 경계, 대규모 감사 읽기 비용과 페이지 조회, 복원 checkpoint 운영 보관을 이어간다. 호스트/OS 재부팅·전원 단절·다중 호스트 분할·원격 WORM은 여전히 미검증이다. 이전8시간 연속 시험도 자동 시작하지 않는다. 원본 평가자료/정답/F1 지표는 바꾸지 않았다.
