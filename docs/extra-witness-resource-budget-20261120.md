# 실측에 따른 witness 수집기 메모리 여유 보완

2026-11-20 · `extra` · 제품 f6e1a0a(설정 변경 c96db35, 사례ID 유지 f6e1a0a). 기본 수집기 MemoryMax를256MiB에서512MiB로 조정했다. CPU50%·Tasks8·프로필/최소 신뢰 기준·서명/권한·네트워크 제한은 동일하다. 키 없는 복원 점검기의 템플릿은256MiB를 유지한다. 실제 AWS/운영 호스트의 메모리를 변경하거나 자원을 생성한 작업이 아니다.

## 선정 근거와 실제 검증

감사 원본100,000행과 서명 control4096개를 같은 fixture에 넣어 함께 시험했다. 감사 payload/해시 체인과 중간4094개 서명은 유효하게 bulk 생성했고 실제 마지막 관측·서명/용량 거부·중간 control 손상 거부·암호화 백업·복원·키 없는 확인을 수행했다. 독립 공격10만 건이나 실제 collector4096회 검증은 아니다. source MAX_ROWS 한도이며 MAX_BYTES256MiB payload 한도까지 채운 시험도 아니다. 감사 DB 전체 bytes 불변은 streaming SHA256으로 확인해 시험 도구가136MB 원본을 한꺼번에 메모리에 올리지 않게 했다.

이 규모 시험에서 암호화 백업한 대상은 control의 profile/public key/observer DB이며, 서명 개인키나10만 행의 감사 원본 DB 자체는 포함하지 않는다. 원본 감사 bytes의 불변과 서명 head 검증을 별도로 확인했다. 원본 감사 데이터 전체의 백업/복원 검증으로 확대하지 않는다.

| 실제 실행 | 고정 제품 소스 | 제한 | 관측한 cgroup 최대 메모리 | 결과 |
|---|---|---|---|---|
| 기존 결합 fixture | b77eceb/2241파일 | 256MiB | 267,689,984bytes, 약255.3MiB | 8조건 통과·limit hit0·OOM0 |
| 조정 후 결합 fixture | f6e1a0a/2498파일 | 512MiB | 269,701,120bytes, 약257.2MiB | 8조건 통과·limit hit0·OOM0 |

기존 실행은 한도까지 약0.7MiB만 남아 입력/환경 변화에 대한 여유가 거의 없었다. 측정값을 근거로 수집기에512MiB 예산을 두었다. 두 실행은 소스 archive/암호 nonce/호스트 동시 부하가 다르므로 메모리/시간의 통제된 성능 비교나 모든 최대 payload의 메모리 상한으로 설명하지 않는다. 조정 후 시험은84.091초였고 서비스 지연 SLA 수치가 아니다. 실제 peak가512MiB 아래였다는 한 fixture의 관측이다.

별도 실제 systemd 템플릿 실행에서도15조건을 통과했다. collector 자기 cgroup에서536,870,912bytes·CPU50%·Tasks8을 확인했다. 비루트·빈 capability·쓰기/읽기·socket/process 접근 거부·SIGKILL 뒤 supervisor 재시작·키 없는 점검/timer도 확인했다. 복원 점검기의256MiB는 템플릿 계약으로 확인했으며 이번 도구가 그 역할의 커널 limit를 별도로 측정한 것으로 표시하지 않는다. /run UUID 소유 unit·상태/public source를 정리했고/etc 설치나 새 계정 생성은 없다.

## 전체 회귀와 출처

설정 변경 직후 c96db35의 Windows 템플릿7조건이 먼저 통과했다. 이후 기존 사례ID를 유지한 f6e1a0a로 전체 소스를 고정했으며, 정적 코드 검사도 오류0이었다. 앞선 집중 검사 XML의 사례 표기와 최종 전체 회귀의 사례 표기를 구분한다.

변경 후 Windows·Linux 전체 pytest는 별도 f6e1a0a archive에서 수행한다. 진행/최종 통과 수·제외 이유·기존 통과ID 비교는 [전체 회귀](extra-until0800-regression-20261120.md)에 갱신한다. 완료 전에는 b77 전체 회귀 수를 새 설정의 결과로 재사용하지 않는다. 두 기존 서비스 계약 사례의 ID는 유지했고 해당 수집기 메모리 기대값만512M으로 조정했다. 같은ID가 이전과 완전히 같은 단언이라는 의미는 아니다.

새 archive2498개는 양 OS expected map이 같았고 Git blob과1083개 bytes동일·1415개 LF→CRLF checkout 관계만 있었다. 추가·누락·기타 내용 차이0이며 실행 파일이나 원본 증거는 변경하지 않았다. 실제 systemd에 공개 staging한 코드774개도 전후 bytes를 확인했다. 전체 archive 파일 수와 제품 코드 파일 수/시험 사례 수는 서로 다르다.

원본 보고서·자기 cgroup 값·systemd 로그/정리·실행기·Git/실행 해시: [검증 명세](infrastructure-results/extra-witness-resource-budget-20261120.json). [이전 규모 검증](extra-witness-boundary-acceptance-20261120.md)·[최초 권한 템플릿 인수](extra-witness-systemd-20261120.md)·[현재 목표](extra-until-0800-20261120.md).

기존 작성형 개발360건 LLM F1 93.41%는 그대로 목표 미달이다. 이번 자원 설정 보완은 탐지 성능 개선/기업 운영 인수/실제8시간 soak를 대신하지 않는다. 유료 API·AWS·Docker 생성·업로드·CI·병합은 없다.
