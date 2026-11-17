# 초기 mTLS 검증 실패의 진단 보강 — 해결 여부 미확정

PR87 병합 전17개 CI는 성공했지만 병합 커밋b3abad3871be881e5978dc4f677d7714880c4f82의 post-merge CI43771249307에서 monitored job132987426509가 실패했다. 첫 성공 조건 전 checks0·runtime_command_failed_1·소유 container/volume/network 잔여0이 보고됐다. 정확한 명령·호출 위치는 원래 보고서에 없어 build/download/start/OOM/TLS 중 어느 원인이라고 확정하지 않는다. 첫 release 검증에서 첫 성공 조건을 기록하기 전에도 명령이 있으므로 runtime.up 내부라고 단정하지 않는다.

테스트 실행기에 operation_stage(runtime_start/runtime_checks/monitoring_checks)를 남기고, 기존 public_failure의 고정 사유·종료번호·제한된 timeout·최대8개 저장소 상대 파일/줄 번호를 failure_detail로 기록한다. 기존 고정 failure 문자열·실패 종료·소유 자원 정리를 유지한다. 명령 인자·stdin·stdout/stderr·로컬 변수·키·토큰·절대 경로는 추가하지 않는다. 서비스/탐지/권한·TLS·대기 한도·재시도 정책을 변경하지 않는다. 최초 단계 표시는 메모리에만 쓰며 런타임 준비보다 앞서 출력 디렉터리를 만들지 않는다.

Windows 및 networknone/UID10001/cap0/NNP Linux Docker에서 같은 집중119건을 각각 통과했다. 신규7건은 기본/monitoring CLI에서 실제 command 래퍼의 비정상 종료, timeout, 값 오류가 실패/정리/비밀값 비노출을 유지하는지 확인한다. 집중 검증을 합산238건 또는 전체6,387건 통과로 표시하지 않는다. 이 변경의 전체/실제 monitored 통합/기존 판정 재실행은 아직 하지 않았다. 이전 PAM 코어의 전체6,380건 결과는 해당 소스에 한정한다.

이 PR은 원래 CI 실패를 해결했다고 주장하지 않는 진단 보강이다. 새 head의 CI와 추가 실패의 세부 위치를 확인한 뒤 원인에 해당하는 수정을 별도로 검증해야 한다. 기존 실패를 단순 재실행으로 성공 처리하지 않았다. AWS/유료 API0·장기 soak 유예를 유지한다.

[원래 실패 job](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/actions/runs/43771249307/job/132987426509) · [검증 결과](infrastructure-results/extra-monitored-diagnostics-v100-20261116.json).
