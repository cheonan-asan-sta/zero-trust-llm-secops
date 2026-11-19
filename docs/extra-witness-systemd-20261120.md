# Witness 수집·복원 점검의 systemd 실행 경계

2026-11-20 · `extra` 구현 `720daff`. 오전08:00까지의 후속 목표는 진행 중이다. 이 단계는 운영 배포가 아니라, 실제 로컬 Linux systemd에서 배포 후보 템플릿의 권한·재시작·점검 주기를 시험했다.

수집 worker와 키 없는 복원 점검을 별도 service로 제공하고 복원 점검에 15초 timer를 추가했다. 실행 계정 후보는 `secops-witness`이며 sysusers 파일도 제공한다. 실제 시험은 기존 daemon UID1을 사용했다. 계정 생성·운영 경로 설치·서비스 enable·/etc 변경은 하지 않았다. 수집기는 서명키를 읽을 수 있으므로 키가 없는 별도 신뢰 주체가 아니다. 복원 점검은 원본 감사/서명키 경로를 숨기고 외부 고정 기준으로 복원 후보만 확인한다.

두 service는 비루트·빈 capability·NoNewPrivileges·읽기 전용 파일시스템·필요한 상태/캐시만 쓰기·개별 네트워크 namespace·AF_UNIX 제한을 사용한다. `/proc`와 다른 프로세스 메모리 접근 syscall을 막고 메모리256MiB·CPU50%·작업8개로 제한한다. 이 제한은 자동 권한 허가나 독립 저장소 보장을 의미하지 않는다.

| 검증 | 실제 결과 |
|---|---|
| 템플릿/플랫폼 가드 | Windows7 / Linux7 통과. Windows 결과는 Linux 커널 인수 결과가 아님 |
| 실제 systemd 권한·읽기/쓰기·socket·프로세스 접근 | 수집/복원 역할별 제한 통과 |
| 실제 kernel 자원 제한 | WSL 혼합 cgroup v1/v2에서 해당 service PID의 메모리268435456bytes·CPU50%·작업8 확인 |
| 강제 종료 후 supervisor 재시작 | invocation 변경, anchor2→3, profile 유지 |
| 실제 키 없는 점검과 timer | 실행2회 및 원래 복원 시작 시각 보존 |
| 실제 검증 합계 | 15조건 통과. 조건 수는 독립 성능 평가 표본 수가 아님 |
| 종료 정리 | UUID로 소유한 /run 임시 unit·상태만 제거. 원본 bytes 유지 |

최초 시험에서 복원 대상 부모를 너무 공개적으로 준비해 private-parent 가드가 거부했다. 먼저 비공개로 복원한 뒤 필요한 접근만 주도록 fixture 순서를 고쳤다. 다음 자원 측정에서 cgroup v2 단독 구성을 가정한 경로가 WSL에서 실패해 기존 혼합 cgroup 공통 측정기를 재사용했다. 실패 원본도 최종 성공 결과와 함께 보존했다. 마지막 재시작 시험은 종료 직전 anchor를 읽고 그보다 진행해야 통과한다.

재현: 소스·의존성이 있는 Linux systemd 환경에서 공개 소스를 `/run/ztw-code-<고유값>`에 준비한 뒤 root로 `python -m scripts.run_witness_systemd_controls --directory <새결과폴더>`를 실행한다. 상세 템플릿은 `infra/systemd/secops-audit-witness*`, probe는 `scripts/witness_systemd_probe.py`다. controller는 범위가 확인된 자체 /run 경로만 만들고 정리한다. 임의 운영 서비스로 실행하면 안 된다.

원본·SHA256·구현 커밋: [검증 명세](infrastructure-results/extra-witness-systemd-20261120.json). 실제 최종 [15조건](infrastructure-results/witness-systemd-native-final-20261120/report.json), [Windows](infrastructure-results/witness-systemd-template-windows-final-20261120.xml), [Linux](infrastructure-results/witness-systemd-template-linux-final-20261120.xml). 642개 fixture 파일의 실제 bytes는 별도 inventory로 남겼다. 작업 트리 CRLF와 Git LF 차이가 있어 inventory를 Git blob 동일성으로 대신 주장하지 않는다.

독립 호스트·외부SSO·원격WORM·운영 설치·8시간 soak는 미완료다. 탐지 정답/예측은 바꾸지 않았고 F1 93.41%는 기존 개발360건 결과로 목표 미달이다. 별도로 d45e91f 전체 회귀에서 Linux8806통과/5제외, Windows8197통과/612제외/2실패를 확인했다. 그 소스는 이번 systemd/주기 수정 전 버전이며 Windows 실패 두 건을 후속 분석 중이다. 유료 API·AWS·Docker·업로드·CI·병합은 없다.
