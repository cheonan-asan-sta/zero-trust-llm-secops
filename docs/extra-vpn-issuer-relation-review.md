# VPN 후보의 단계별 지지 감사와 근거 수집 — v125

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 목표 active · 목표 전 push/새 CI/병합 보류

**새 성능 개선은 채택하지 않았다.** 초기 후보의 Harrison/Wheeler 오탐 각5행 감소는 단계별 최소 지지를 충족하지 못해 미채택이다. 후보가 계산한 정상24행은 issuer/KU/EKU/검사/목적/leaf의 서로 다른 여섯 단계에 각4행이었다. 24를 단계별 지지로 사용할 수 없다. 수정 후 원래1,681,815행과 별도5개 자료를 유지한9개 묶음 비교에서 모든 판정이 v124와 같았다. 공유 감사·VPN F1은 각각80%다.

## 구현과 검증 기준

같은 source·연결의 앞선 서버 `VERIFY OK` subject와 현재 issuer subject의 관측 관계만 다루는 검토용 profile을 만들었다. subject/IP/port/CN/hash의 실제 값, source 경과시간, 클라이언트 OS/version을 학습하지 않는다. 원문·행 ordinal·source SHA·원문 행 SHA와 기존 protocol 관측에 결속하고, 새 initial/다른 연결/재시작/순서·시각 오류·만료를 보수적으로 처리한다. issuer 관측은300초, subject 관계 이력은24시간으로 고정했다. client claim으로 만료를 갱신하지 않으며 기존 실패 보호60/61초를 유지한다.

[OpenVPN 검증 logger](https://github.com/OpenVPN/openvpn/blob/v2.4.4/src/openvpn/ssl_verify.c)와 [OpenSSL 연동](https://github.com/OpenVPN/openvpn/blob/v2.4.4/src/openvpn/ssl_verify_openssl.c)은 관측 형식의 참고 근거다. 실제 binary byte 신원이나 모든 chain 검증 완료를 증명한 것은 아니다. 기록된 subject는 인증서 fingerprint가 아니며 같은 subject가 같은 key·기기·사람·현재 권한이라는 뜻도 아니다. 검토 상태와 `automatic_enforcement_allowed=false`를 유지한다. 운영 기본 탐지기·PDP/PEP·권한은 변경하지 않았다.

선언한 R/S/Shaw/Wheeler training35,633 VPN 행만 사용했다. 모든 관측을 봉인한 뒤 기존 training truth를 열어 적합하며 Fox/Harrison/Wardbeck 역할을 학습으로 바꾸지 않았다. source SHA 중복·원문/준비/정답 변조를 거부한다. v109/v114 기존 가중치는 변경하지 않았다.

| 최초 issuer 관계의 현재 단계 | 정상 지지 | 공격 지지 | 최소 정상5 충족 |
|---|---:|---:|---|
| issuer |4|0|아니오|
| KU |4|0|아니오|
| EKU 검사 |4|0|아니오|
| EKU 목적 |4|0|아니오|
| EKU OK |4|0|아니오|
| leaf |4|0|아니오|

나머지 반복 관측 셀에는 공격도 있어 완화 veto다. 따라서 정상 보정 가능한 셀은0이다. 초안은 단계들을 합쳐 별도 Harrison/Wheeler에서 각5행을 낮췄지만, 이 결과는 **허용 기준을 충족한 개선이 아니다**. 초안 score/model/commit을 보존해 수정 이유를 추적한다. 현재 profile2/schema2는 단계별 key와 지지를 분리하고, 구형 pooled 모델·다른 단계의 projection 재사용·EKU 목적 불일치를 거부한다. 기능 시험의 합성 지지를 실제 탐지 F1이나 training 표본에 더하지 않았다.

## 실제 비교 결과

| R/S/F 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 공유 감사 |4|0|2|100%|66.6667%|80%|0%|33.3333%|
| 웹 감사 |47|0|0|100%|100%|100%|0%|0%|
| 인증 |32|0|0|100%|100%|100%|0%|0%|
| VPN |84|42|0|66.6667%|100%|80%|0.2286%|0%|

수정한9개 전체 비교에서 추가TP/FP·TP손실·FP감소0, 추론 오류0이다. 별도 Harrison VPN은TP28/FP36/FN0, Wheeler training은TP47/FP36/FN9로 유지한다. 초안의 FP31을 최신 성능으로 쓰지 않는다. 원래 라벨·행·ID·순서·분모·95%/5% 목표를 유지했다. 원래6영역의 새 독립 인수는 이 표와 별도이며 계속 미완료다.

## 추가 조사로 확인한 근거 공백

서버 메시지 현재 template·앞선2/4개 연결/peer 순서 후보 네 개는 training 및 출처하나제외 비교에서 개선0이었다. 지원된 초기/검증 셀은 정상14/위협4로 혼재했다. 이 결과는 시험한 특징의 한계이며 모든 원문/새 근거에서도 불가능하다는 증명은 아니다.

고정된 주소 용도 분류도 조사했지만 R/S/Shaw/Wheeler 정상·위협이 모두 RFC1918 범주였다. 특정 실제 IP/서브넷을 공격 예외로 학습하지 않았고 private 주소라는 이유로 신뢰하지 않았다.

이미 완전히 검증한 R archive의 client 자료 목록도 확인했다. remote employee 세 파일에는 state-machine wrapper 안의 실제 OpenVPN stdout5903행이 있었다. 하지만 root의 PID/UID·socket inode/local endpoint·device ID·SSO subject/issuer/audience·signature/collector receipt 필드는 없었다. 이 조사 범위의 결과이며 모든 외부 자료에 근거가 없다는 뜻은 아니다.

wrapper에는 run/seed/state/target/transition/vpn_cmd 같은 계획·시뮬레이션 문맥도 있어 **stdout을 포함한 이 세 파일 전체를 모델 학습/예측에서 제외**했다. 파일명에 employee가 있다는 이유로 정상 사용자·기기 권한을 채우거나 그 파일의 존재를 정상 특징으로 사용하지 않았다. [노출 대장](../infra/f1-lab/observed-source-exposure-v125.json)은 이 세 source 지문을 추가해61→64로 기록하고 source ID/payload769/pattern601은 보존했다. 소비한8개 testbed의 추가 modality이며 새 독립 source는 아니다.

## 추가 위험 유지 후보

동결 공격 셀의 지지5·정상0 근거를 기존 경보 여부와 무관하게 기록하고, 연결/peer 범위 및 timestamp가 유효한 unbound 행을 유지하는 후보도 training에서 시험했다. 먼저 기존60초를 유지했고, 별도 고정60/300/900초 후보도 비교했다. source/peer 값은 연결에만 쓰며 학습하지 않고, 현재보다 앞선 시각·첫 근거 기준의 비갱신 만료와 source 재시작 초기화를 유지했다. 60/300초는 개선0, 900초는 Wheeler에 새FP2·TP개선0이어서 모두 미채택했다. 기존 native 실패 보호60초와 운영 코드는 변경하지 않았다.

## 실제 시험과 다음 작업

관련 Linux **1,244건·Ruff+RUF100 통과**, 실패/error/skip0이다. v124 이후 새54건은 단계별4/5 지지·공격 veto·서명 지문/의존 모델/role 변조·단계 간 지지 차용·EKU 불일치·source/원문/순서/시각·초기화/만료·실패60/61초·검토 유지/권한 비부여를 검사했다. 프로젝트 전체 기능을 새로 모두 시험했다는 뜻은 아니다.

최종 기능 시험과 같은 app/scripts 바이트와 frozen parameter를 기존 cached image의 network none·UID10001·read-only·cap-drop·CPU2/2GiB에서 예측했다. image의 옛 프로젝트/설치 사본과 문서/테스트/평가 정답·집계를 차단하고 예측을 봉인했다. 소유 컨테이너 제거 후에만 원래 truth로 채점했으며 source/archive/입력 불변을 확인했다. 새 image build/pull은 없었다.

다음은 단계별 자연 표본/선행 실행·호출 신원·기기 권한 근거를 추가로 확보하고, 이미 지원된 공격 근거의 인과적 위험 유지 경로를 training에서 먼저 검토하는 것이다. 현 자료의 부족을 미래 stdout·simulator state·표본 복제·역할 변경으로 채우지 않는다. 공유 감사 Fox FN2는 가까운 인코딩 질의가9.046초 전이므로 기존5초 조건을 늘려 맞추지 않는다. VPN FP42와 별도 Wheeler FN9, 원래6영역·5축·source/label 심사는 남아 있다.

LLM의 새 품질 향상은 측정하지 않았다. 유료/provider·AWS·push·새 CI·병합·8시간 soak는0이다. 요청한 Docker 정리는 v122에서 완료했고 이번 소유 시험/예측 컨테이너도 제거했다.

[전체 JSON](infrastructure-results/extra-vpn-issuer-v125-20261117.json) · [실제 JUnit](infrastructure-results/extra-vpn-issuer-v125-20261117.xml) · [동결 계약](../infra/f1-lab/vpn-issuer-contract-v125.json) · [재현](vpn-issuer-test-guide.md)
