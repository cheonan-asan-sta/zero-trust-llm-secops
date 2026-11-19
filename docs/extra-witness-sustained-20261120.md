# 기본 주기 수집 프로세스의 지속 실행과 재시작

2026-11-20 · `extra` · b77eceb 제품 소스 고정. 짧은 CLI 호출과 별도로 수집 프로세스를 계속 유지했을 때 기본60초 주기/180초 신선도·공개 상태 갱신·같은 신뢰 기준의 강제 종료 재개를 확인한다. 실제8시간 soak·독립 호스트·탐지 성능 시험은 아니다.

## 절차와 현재 결과

먼저4분 사전 실행에서 두 차례 SIGKILL과 재시작·중간 감사 원본 추가·기본 주기를 확인했다. 수정 후 사전 실행은240.164초·watch5회·상태 표본23개로 완료됐고, 비공개 fixture와 소유 자식 프로세스가 정리됐다. 이어 별도 fixture에서100분(6000초)을 요청했다. 전체 실행의1/5·3/5 시점에 소유한 수집 프로세스를 SIGKILL하고 같은 control·공개키·profile pin·최소 receipt로 다시 시작한다. 첫90초 뒤180초마다 합성 감사 행을 추가하며, 10초마다 공개 status/경보와 별도 실제 control 상태를 확인한다. 새로운 source 행이 아직 수집되지 않았으면 unobserved를 그대로 기록한다. 공개 snapshot의 정상/신선도와 source의 즉시 일치를 혼동하지 않는다.

실행 중. 미완료 단계를 통과로 집계하지 않는다.

종료 직전 상태를 before_final_drain으로 먼저 보존한 다음, 별도 실제 cycle을 명시적으로 한 번 실행해 남은 행을 관측한다. 이 최종 drain을 장시간 watch가 이미 완료한 수집으로 합산하지 않는다. 각 watch 로그의 실제 완료 행/실패 여부·마지막 원본 행 수·최종 미관측0·프로필 검증·추적2241개 파일 전후 SHA256을 확인한다. 정상/위협 평가 정답이나 분모를 변경하지 않는다. RSS는 관측한 자식 PID의/proc 값이며 cgroup peak·메모리 상한·누수 부재 증명이 아니다.

## 사전 도구 오류와 범위

최초 도구는 실제 지표 secops_witness_observation_action_required에서 observation을 빠뜨려10.140초에 실패했다. 제품 watch의 첫 수집은 정상이며 원본 실패/도구v1을 보존했다. 또 공개 status에 없는 source_head를 읽지 않도록 실제 감사 head 검사와 unobserved_rows 검증을 사용했다. 제품 소스를 수정하거나 기대 경보를 약하게 바꾼 것이 아니다. 수정한 도구가4분 사전 절차를 완료한 경우에만100분 실행을 시작하도록 연결했다.

사람의 외부SSO·원격 불변 journal·운영 systemd 자동 재시작 인수·전원 장애는 이 도구의 대상이 아니다. 재시작은 시험 부모가 소유 Popen으로 수행한다. 별도 실제 systemd 권한/자동 재시작 시험 및256MiB 자원 제한 결과는 각 문서에 남겼다. 유료 API·AWS·Docker 생성·업로드·CI·병합은 없다. 기존 개발360건 LLM F1 93.41%는 목표 미달인 상태 그대로다.

원본 로그·상태 표본·실행기·소스 SHA256: [검증 명세](infrastructure-results/extra-witness-sustained-20261120.json). [현재 목표](extra-until-0800-20261120.md)·[고정 소스 전체 회귀](extra-until0800-regression-20261120.md)·[systemd 권한 경계](extra-witness-systemd-20261120.md)·[대용량 자원 제한](extra-witness-boundary-acceptance-20261120.md).
