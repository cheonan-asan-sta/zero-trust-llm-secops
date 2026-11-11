# 세션을 나눈 활동의 사용자 단위 shadow 초안

기존 `TemporalStore`는 세션 안에서 로그인 실패·다운로드 증분·서로 다른 자원을 센다.
v9는 위험 기기/비활성 신원 이력을 새 세션에도 전달하지만 활동량 자체는 세션 단위였다.
새 `SubjectTemporalStore` / `SubjectShadowDetector`는 이를 바꾸어 비교할 **선택형 로컬 초안**이다.
기존 앱·규칙·기본 임계값·라벨·기존 실험 프로필을 변경하지 않는다.

## 범위와 관측 계약

집계 키는 **같은 저장소의 tenant + 인증된 analyst subject + 관측 사용자 ID**다.
10분 동안 받은 이벤트를 세션/기기가 달라도 합산한다. 실제 LOGIN 실패 이벤트를 세며,
서명된 다운로드 증분을 합산하고 서로 다른 자원 ID를 센다. 스냅샷의 누적 숫자를 더하지 않는다.
기존 세션의 사용자/기기 고정·tenant 안의 이벤트 ID 중복/충돌·출처 권한·60초 신선도 검사는 유지한다.
세션 변경만으로 이미 받은 같은 사용자의 활동량을 초기화할 수 없다.

다른 tenant/analyst/user의 활동량은 합치지 않는다. 같은 tenant의 관련 기기 위험/사용자 비활성은
기존처럼 파생 상태로만 전달하며 다른 운영자의 원문 event/session/resource ID는 공개하지 않는다.
같은 사용자의 창에 포함된 여러 기기의 위험도 확인한다.
관측 출처가 주장한 사용자 ID를 신뢰 뿌리로 사용하므로 실제 IdP의 사용자 연결·서비스 계정 공유·
프록시/위임 식별·다른 수집 경로의 동일 이벤트 정규화는 별도 인수해야 한다.
여러 운영자/저장소/호스트를 아우르는 기업 전체 상관 분석은 구현 범위가 아니다.

## 더 넓어진 승인 범위

업무 승인은 정확한 현재 이벤트와 현재 창의 사실 지문을 모두 가리켜야 한다.
`SubjectApprovalVerifier`는 기존 사용자·자원·행위·유효 시간·폐기·다운로드 상한 검사에 더해
**창에 포함된 모든 기기**가 승인 발급자의 위임 범위 안에 있는지 검사한다.
현재 기기/현재 자원만 담당하는 승인이나 현재 이벤트만의 승인은 이전 활동량을 덮지 못한다.
새 관련 관측·만료·권한 변화는 사실 지문/완전성에 반영한다. 무관한 사용자의 정상 journal 증가만으로
같은 사실 지문을 바꾸지는 않는다. 창 승인도 침해 기기·비활성 신원·거부 MFA·자원 소유자 거부를 없애지 않는다.

확대된 창을 기존 승인 검증기에 잘못 연결하지 않도록 공개 요약의 `complete`는 항상 false다.
별도 `subject_evidence_complete`는 받은 사실의 현재 권한 상태이며 실제 수집 완전성은 아니다.
전용 detector가 검증된 저장소에서 직접 받은 요약의 내부 복사본만 평가한다.
기존 detector/승인 도구를 연결하면 불완전 경보를 내고 확대 창 승인을 거부한다.
전용 detector는 기존 verifier/store와 raw 이벤트 경로를 거부한다. 외부 클라이언트 요약 입력 API는 없다.

## 로컬 구성 예시

```python
store = SubjectTemporalStore(database, control, frozen_source_verifier,
                             configured_delta_producers, resource_policies=pinned_policy)
store.initialize()  # 새 저장소/별도 witness. 기존 세션 프로필을 재사용하지 않음
approvals = PinnedSubjectApprovalVerifier(public_registry, external_sha256, minimum_version=1)
detector = SubjectShadowDetector(temporal_store=store, approval_verifier=approvals)
result = detector.evaluate_signed(signed_event, authenticated_analyst)
```

이는 SDK/앱 운영 연결 예시가 아니라 로컬 시험의 객체 구성이다. 비밀키를 detector 입력에 넣지 않는다.
새 profile/config 지문을 witness에 묶으므로 기존 프로필로 같은 저장소를 다시 열어 의미를 조용히 바꿀 수 없다.
현재 bounded journal은 최대2,000행이며 용량을 넘으면 실패한다. 보관/압축/여러 호스트 동시 쓰기는 별도다.
시계 high-water와 원장/witness 복구 경계는 상속하지만 디스크/전원/전체 control 동시 롤백 안전성은 주장하지 않는다.

## 검증 범위와 성능 수치

새 집중 시험은39개다. 세션/기기 분할 로그인·유출·fanout, tenant/주체 격리, 전체 기기/자원/상한 승인,
승인 폐기·자원 정책 거부·하드 위험, 동시 재시도, 네 지점 실제 worker 종료, 시간 만료/회귀를 확인한다.
최초19개 실패는 시험 fixture의 잘못된 네트워크 값/registry 구성이고, 다음 regex/MFA fixture 실패도 보존했다.
보완 후39개 집중 시험과 최종 묶음 회차는 합산하지 않는다.
정확한 최종 운영체제별 결과/소스는 [v11 공개 결과](infrastructure-results/extra-subject-v11-20261112.json)를 따른다.

이 변경의 결과는 **shadow 경보**다. 실제 권한 부여/회수·세션 변경·AWS/유료 API 호출은 없다.
기능 반례를 새 독립 F1 데이터로 세지 않는다. 기존 holdout의 원본 F1 56.25%·세션 후보와 별개인
raw shadow 진단80%·FPR33.33%를 이39개 기능 시험으로 교체하지 않는다.
새 사용자 단위 metric을 보고하려면 분모(사용자/시간 구간), 실제 정상 업무 승인, 사용자 식별 신뢰,
미수집 이벤트/오류 처리, 새 독립 자료와 라벨 검토를 먼저 고정해야 한다. 목표 달성은 미확인 상태다.
08:50 종료 예정 장시간 시험은 이전 고정 v9 세션 프로필이다. 이 새 프로필의 장시간 시험 완료로 해석하지 않는다.
