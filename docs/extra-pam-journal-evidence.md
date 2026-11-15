# PID가 빠진 PAM 로그를 보완하는 journal 관측

최신 통합 검증은 전체6,332·집중475개와 실제 PAM18조건(기존12+지속 대장6)을 통과했다. 최초 Group=nobody/216/GROUP 실패는 실제 UID/GID를 조회하도록 수정한 이전 실행이며 최신 결과와 합산하지 않는다. [현재 구현·검증·남은 작업](infrastructure-current-state-20261116.md)에서 전체 범위와 지문을 확인한다.

## 최초 실행 실패와 조치 기록

첫 고정 소스의 집중189개는 통과했으나 native는 Python 시작 전 실패했다. 시험 unit에 `Group=nobody`를 지정했지만 Ubuntu의 해당 계정 GID65534 이름은 `nogroup`이었다. 소유 unit의 실제 journal에서216/GROUP을 확인했고 해당 시도의 unit/공급자/상태/소스를 정리했다. 시험 unit은 실제 계정의 UID/GID를 조회해 지정하도록 수정했다. 시작 실패 시에도 고정된 manager 상태/종료번호를 CLI 결과보다 먼저 남기며, 그 뒤 새 출력/소스로 재검증했다. 당시에는 전체/native 인수 미완료로 표시했다.

## 출발점과 수집 경계

v85의 관측 개발 인증 미탐3행은 모두 PID가 없는 `sudo` PAM open 메시지다. 보고된 opener UID0과 본문만으로는 실제 호출 사람·어느 sudo 실행인지 구분할 수 없다. 주변 su나 sudo 행에 임의로 붙여 미탐을 없애지 않는다. v92에서는 현재 점수의 모든 임계값으로도 목표를 만족할 수 없음을 확인했다. 이 작업은 앞으로 수집하는 자료의 출처·PID·실행 회차를 보완하며 과거 행의 누락 필드를 채우거나 F1을 소급 갱신하지 않는다.

로컬 systemd journal의 **한 boot·한 unit invocation·제한된 시간창**에서 PAM open/close 관측을 수집한다. `SYSLOG_IDENTIFIER`·`SYSLOG_PID`·MESSAGE의 자기 주장으로 프로세스를 인증하지 않는다. `_PID/_UID/_GID/_COMM/_EXE/_SYSTEMD_UNIT/_SYSTEMD_INVOCATION_ID/_BOOT_ID`를 확인하고, stdout 부모 연결의 PID 모호성을 피하려고 `_TRANSPORT=syslog`만 수용한다. 같은 PID의 open/close를 하나의 인증 세션이라고 자동 결합하지 않는다. PID 생애 식별자·사람의 SSO·당시 업무 승인은 별도 근거다.

[systemd255의 journal 필드 명세](https://www.freedesktop.org/software/systemd/man/255/systemd.journal-fields.html)는 underscore 필드의 생성 주체, syslog 호환 필드의 비검증성, stdout/stderr 상속 연결의 PID 한계를 설명한다. [Linux-PAM 원본 구현](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/pam_unix_sess.c)은 PAM 대상 계정과 opener/getuid를 로그에 남긴다. 이 값은 IdP로 확인한 사람의 로그인 신원이나 명령의 승인 증명이 아니다. 문법을 직접 검증하며 외부 코드를 복사하지 않는다.

## 실제 사전 관측

소유한 일회성 unit에서 `logger -t sudo`로 같은 PAM 본문을 만들고, 실제 sudo로 nobody 권한의 고정 sleep을 실행했다. 양쪽 모두 표면상 sudo 메시지였지만 journal의 실제 `_COMM`은 logger/sudo로 달랐다. 실제 sudo open/close에는 같은 보고 PID와 unit invocation·boot, 서로 다른 원래 microsecond 시각·cursor가 있었다. audit login UID/session은 이 WSL에서 제공되지 않았다. 미상 값은 None으로 남긴다. source unit을 제거했고 sudoers/PAM/호스트 audit 설정은 바꾸지 않았다.

## 구현 계약

새 `authentication` 서명 역할을 기존 runtime/authorization와 분리한다. 전용 key/source와 정확한 tenant/server/unit 범위를 현재 공개 registry에서 검증하며 기존 실행·권한 서명키는 수집에 사용할 수 없다. 새 capture의 schema·서명 domain도 실행 증거와 다르다. 유효한 새 capture를 기존 ProcessObservation·ServiceProof·권한 승인으로 사용할 수 없다.

collector CLI는 로컬 journal에 고정된 읽기 명령만 실행한다. key는 anonymous stdin 또는 전용 systemd memory credential에서 받으며 file/argv/환경/출력에 복사하지 않는다. key 없는 verify 경로는 공개 registry·scope·예상 boot/invocation·capture SHA로 서명과 현재 신뢰/기간을 검사한다. 입력 JSON 파일을 로컬 journal로 간주해 수집하는 모드는 없다. parser fixture는 단위 시험용이고 자체로 출처를 인증하지 않는다.

보고된 계정은 digest로 보존하며 익명화를 보장하지 않는다. 원래 메시지·argv·개인키는 capture에 저장하지 않는다. 원래 시각·전송·보고 PID/UID·unit/boot/invocation·cursor/내보낸 필드 지문과 명시적인 미상 값을 저장한다. 원본 journal 파일의 암호학적 seal 검증이나 원격 attestation을 주장하지 않는다. 신뢰하는 로컬 collector·journal·커널·관리자가 경계다.

읽기 시간·행·행 크기·전체 크기를 제한하고 초과/잘림/중복 cursor/시간 역행/수집 중 invocation·trust 변경을 거부한다. 표면상 PAM이지만 출처가 맞지 않는 메시지는 미인증 관측으로 집계하며 정상으로 라벨링하지 않는다. 확인된 PAM0건도 정상/안전/승인 완료가 아니다. 출력은 새0700디렉터리/0600파일로 만들며 기존 실행 capture의 latest를 갱신하지 않는다.

이 수집은 선택형 인프라 기능이다. 자동 경보 등급 변경·권한 발급/회수·명령 실행·실제 사람 인증·기존 F1 판정 변경을 하지 않는다. 새 역할의 공급자 HA와 기존 장기 보관/암호화 백업 연결은 별도 인수이며 runtime 키 공급자 HA를 그대로 재사용했다고 주장하지 않는다. AWS/유료 API0, 장기8/12시간 soak는 유예한다.

[집계·소스 지문·실행 근거](infrastructure-results/extra-infrastructure-overnight-v97-20261116.json)에서 최종 소스와 실제 통합 결과를 확인한다.

수집 CLI는 `scripts.collect_pam_journal`, 별도 키 없는 검증 CLI는 `scripts.verify_pam_journal`이다. 선택형 `secops-pam-journal@.service/.timer`는 전용 `secops-auth-collector` 계정·journal 읽기 그룹·capability0·NNP·전용 memory credential을 가정하며 설치/계정 생성/enable을 자동 수행하지 않는다.30초 주기와60초 창은 겹칠 수 있다. 반복 관측은 같은 cursor·원래 시각으로 남고 새 인증 사건이나 새 F1 표본이 아니다. [지속 cursor 대장](extra-pam-observation-ledger.md)은 구현·실제 별도 프로세스 검증을 완료했다. 전체 journal 보존/회전 인수·외부 암호화 백업/복원 소비자는 후속이다.

서명 역할 분리는 키가 안전하게 관리된다는 전제의 암호학적 범위다. root·커널·journal 관리자와 기존 SYS_PTRACE/DAC_READ_SEARCH 권한의 호스트 센서는 신뢰 경계다. 이 센서로부터의 물리/OS 키 격리까지 검증한 것으로 표시하지 않는다. 새 전용 계정 템플릿과 로컬 nobody/daemon 시험을 운영 계정/ACL 설치 완료와 구분한다. systemd의 runtime memory credential은 메모리 파일이며 collector가 출력에 개인키를 기록하지 않았다는 설명과 별개다. 원래 시스템 journal에는 PAM 메시지가 남는다. 새 capture에 원문/argv를 추가 저장하지 않는다는 범위다.
