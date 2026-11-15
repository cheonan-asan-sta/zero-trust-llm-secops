# PAM 관측의 지속 보관과 중복 방지

같은 60초 창을 30초마다 수집하면 같은 journal 사건이 여러 서명 capture에 반복된다. 새 `PamObservationLedger`는 이를 새로운 로그인·공격·F1 표본으로 중복 집계하지 않기 위한 선택형 로컬 저장 기능이다. 탐지 점수·기존 라벨·임계값·권한 집행은 변경하지 않는다.

## 사건·capture·신뢰 경계

사건 ID는 명시한 tenant/server/source/unit과 원래 boot·journal cursor 지문으로 만든다. 같은 cursor의 원래 시각·PID·UID·invocation·메시지 지문이 달라지면 충돌로 거부한다. journalctl의 JSON 필드 순서가 바뀔 수 있으므로 내보낸 바이트 지문은 각각의 서명 capture에 보존하고, 사건 비교에는 원래 필드의 의미를 사용한다. 같은 본문·PID라도 cursor가 다르면 별개의 관측이다. open/close를 인증 세션으로 자동 결합하지 않는다.

새 capture는 기존 authentication 전용 서명·외부 registry SHA·scope·예상 boot/invocation·원래 유효기간을 현재 시각에 검증한 뒤 저장한다. 명시적으로 등록한 새 key_id로 같은 출처의 capture를 제출해도 기존 cursor 대장은 유지한다. 새 키 자동 선택·등록·폐기한 키 재활성화는 없다. 현재 신뢰가 바뀌거나 완료 시점에 capture가 만료되면 transaction을 성공 처리하지 않는다.

`scripts.admit_pam_journal`은 공개 신뢰와 외부 capture SHA만 받는 별도 키 없는 CLI다. `--initialize`는 새 비공개 디렉터리를 한 번 만들 때만 사용하며 기존 DB를 초기화하지 못한다. SQLite transaction/고유 사건 ID로 재시작·동시 중복 제출을 처리한다. 원래 capture의 재제출은 원래 시각을 유지하는 duplicate 영수증이며 최신 capture를 되돌리거나 새 사건을 늘리지 않는다. 실제 개인키·토큰·원문·argv를 저장하지 않는다. 계정 digest의 익명성은 보장하지 않는다.

## 보관·오류·한계

디렉터리0700·DB0600·현재 소유자·단일 hardlink·비 symlink, 고정 SQLite application ID/schema·외래키·rollback journal·FULL synchronous를 확인한다. capture/사건 수와 DB64MiB 한도를 넘으면 삭제·덮어쓰기 없이 실패한다. 저장된 capture SHA·모델·사건 지문·첫 출처·전 모집단·순서·중복 수·최신 metadata를 inventory에서 대조하고, 새 admission 전에도 점검한다. 무결성 오류를 정상/빈 관측으로 바꾸지 않는다.

이것은 신뢰하는 로컬 소유자·OS·시계의 관측 대장이다. 관리자에 의한 일관된 전체 DB 재작성·이전 DB 전체 복원에 대한 rollback 방지나 외부 witness를 구현했다고 주장하지 않는다. inventory는 보관한 바이트의 대조이며 과거 capture의 현재 신뢰/신선도 재승인, 실제 사람의 SSO, 정상/위협 라벨, 명령 승인, 자동 차단이 아니다. 외부 암호화 사본·복원·보존 정책·운영 설치와 연결하는 것은 별도 인수다. 기록을 지워서 용량을 자동 확보하지 않는다.

## 검증

재시작/동시 제출·창 겹침·원문 의미가 같은 JSON 재직렬화·cursor 충돌·새 invocation·명시적 키 교체·원래 시각·만료·시계 역행·손상/외부 schema·링크/권한·저장 한도·실제 CLI를 묶어 검사한다. 실제 systemd 시험은 원래 collector에 전용 키만 주고, 별도 daemon UID1/capability0/NNP 프로세스에서 공개 capture를 받아 DB를 쓴다. 첫2건→중복0건→새 invocation2건→새 키의 같은 사건0건, 총 원래4건 보존을 확인한다. 합성 parser 검사와 실제 OS 프로세스 검증을 구분하고 최종 결과는 실행 후 기록한다. AWS/유료 API는 사용하지 않으며 8/12시간 soak는 유예한다.
