# 기업·공공부문 적용 참고자료 카탈로그

- 조사 기준일: 2026-09-16
- 대상: `zero-trust-llm-secops` 0.13.0, `aitest` 브랜치
- 범위: 국내 공공기관·금융권, 해외 정부·표준기관, 기업 실무 프레임워크, 동료심사 논문, 공개 평가 데이터
- 목적: 자료를 나열하는 데 그치지 않고 현재 프로젝트의 통제, 시험, 운영 증적으로 전환한다.

> 구현 반영: 버전 0.8.0에서 18개 통제와 보증 API, 0.9.0에서 OCSF 1.9.0과 Sigma 2.1 데이터 계보, 0.10.0에서 고정 공개 로그 회귀와 OCSF Incident Finding, 0.11.0에서 규칙별 정량 품질 게이트, 0.12.0에서 엔터티 그래프와 다중 시간창, 0.13.0에서 사건 분류·시간창·그래프·중복 제거 품질 게이트를 연결했다. 사건 양성 데이터셋은 아직 1개뿐이며 현재 지표는 인증이나 규정 준수 선언으로 사용하지 않는다.

## 1. 먼저 읽을 결론

이 프로젝트가 기업 또는 공공기관에서 쓰일 수준으로 가려면 다음 문서 묶음을 함께 적용해야 한다.

1. **국내 적용 기준**: KISA 제로트러스트·AI 보안, 개인정보보호위원회 AI 개인정보 위험관리, NIA 공공부문 AI 도입, 금융보안원 AI·클라우드 안내서
2. **보안 관리체계**: ISMS-P, NIST CSF 2.0·SP 800-53·SSDF, ENISA NIS2 구현 가이드
3. **AI 고유 위험**: NIST AI RMF·AI 100-2, 영국 AI 사이버보안 코드, ETSI EN 304 223, MITRE ATLAS, OWASP LLM Top 10
4. **운영 증거**: CISA·NSA 로그 및 제로트러스트 지침, 사고대응 플레이북, 모델·프롬프트·정책·데이터 버전 기록
5. **검증 방법**: AI Verify, NIST ARIA, UK Inspect AI, AgentDojo, 공개 보안 로그와 재현 가능한 공격 실험

가장 중요한 원칙은 `문서를 준수한다고 선언`하는 것이 아니라 각 요구사항을 **통제 ID → 책임자 → 구현 → 자동 시험 → 증적 → 예외와 만료일**로 연결하는 것이다.

## 2. 자료를 해석하는 기준

| 표기 | 의미 | 이 프로젝트에서의 사용법 |
|---|---|---|
| 법령 | 적용 범위에 따라 법적 의무가 될 수 있음 | 실제 사업·고객·지역이 정해지면 법무·개인정보 담당자가 최신 원문으로 재확인 |
| 최종 표준·정부 지침 | 기관이 확정해 공개한 기준 | 통제 요구사항과 합격 기준의 1차 근거 |
| 초안·생활문서 | 변경될 수 있는 공개 초안 또는 지속 갱신 자료 | 설계 참고만 하고 버전과 조회일을 기록 |
| 산업 프레임워크 | 기업·비영리 조직의 실무 지침 | 위협 모델, 질문지, 시험 항목을 빠르게 만드는 데 사용 |
| 동료심사 논문 | 학회·저널 심사를 거친 연구 | 기술 선택과 실험 설계의 근거. 운영 환경에서 별도 재현 필요 |
| 공개 데이터·도구 | 재현 가능한 시험 자원 | 라이선스와 재배포 조건을 확인한 뒤 로컬 Docker 평가에 사용 |

이 문서는 법률 자문이나 인증 판정을 대신하지 않는다. 법령, 인증 기준, 초안, 생활문서는 실제 도입 시점에 최신 버전을 다시 확인해야 한다.

## 3. 우선순위가 가장 높은 15개 자료

| 순위 | 자료 | 당장 가져올 항목 | 만들 증적 |
|---|---|---|---|
| 1 | [KISA 제로트러스트 가이드라인 2.0](https://www.kisa.or.kr/2060204/form?page=1&postSeq=18) | 식별자·기기·네트워크·시스템·데이터·가시성/분석의 성숙도 | 제로트러스트 통제표와 현재/목표 성숙도 |
| 2 | [KISA AI 보안 위협 대응 매뉴얼](https://www.kisa.or.kr/401/form?lang_type=KO&postSeq=3712) | AI 위협 분류, 점검, 산업별 시나리오, 완화책 | AI 위협 모델과 공격 회귀시험 |
| 3 | [개인정보보호위원회 AI 프라이버시 위험관리 모델](https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20799) | 수명주기별 개인정보 위험 식별·측정·완화 | 데이터 흐름도, 개인정보 영향 검토, 보존·삭제 시험 |
| 4 | [NIA 공공부문 AI 도입·활용 가이드](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=29526&cbIdx=37989) | 기획·계약·구축·운영·모니터링·예산 전 과정 | 공공 도입 체크리스트와 공급자 요구사항 |
| 5 | [금융보안원 금융분야 AI 보안 가이드라인](https://www.fsec.or.kr/bbs/detail?bbsNo=11240&menuNo=69) | 금융 데이터와 AI 수명주기 보안 통제 | 금융권 적용 차이 분석과 고위험 승인 규칙 |
| 6 | [ISMS-P 인증기준 안내서](https://isms.kisa.or.kr/ntcn/rcsrm/selectGnrlRcsrmList.do) | 관리체계, 자산·위험, 접근통제, 사고, 개인정보 생명주기 | 통제대장, 운영명세서, 증적 위치 목록 |
| 7 | [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) | Govern부터 Recover까지 조직 위험관리 구조 | 통제 소유자와 KPI가 포함된 CSF 프로파일 |
| 8 | [NIST SP 800-53 Rev.5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | 접근통제·감사·구성·사고·공급망 통제 카탈로그 | 선택 통제와 구현·시험·증적의 추적표 |
| 9 | [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) | 생성형 AI·기반모델을 포함한 안전한 개발 관행 | AI SDLC 게이트와 출시 전 보안 점검 |
| 10 | [CISA Zero Trust Maturity Model v2](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf) | 전통적·초기·고급·최적 성숙도와 교차 기능 | KISA 기준과 교차 매핑한 성숙도 백로그 |
| 11 | [NCSC·CISA 공동 Secure AI System Development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) | 안전한 설계·개발·배포·운영 4단계 | AI 기능별 설계검토 및 운영 종료 체크리스트 |
| 12 | [영국 AI Cyber Security Code of Practice](https://www.gov.uk/government/publications/ai-cyber-security-code-of-practice/code-of-practice-for-the-cyber-security-of-ai) | 책임, 자산, 데이터·모델·프롬프트 문서화, 시험, 모니터링, 폐기 | AI 자산대장과 13개 원칙 자체평가 |
| 13 | [MITRE ATLAS](https://atlas.mitre.org/) | AI 공격 전술·기법·사례·완화책 | ATT&CK + ATLAS 통합 위협·시험 카탈로그 |
| 14 | [OWASP LLM Top 10 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) | 프롬프트 인젝션, 정보노출, 공급망, 과도한 권한 등 | API·프롬프트·도구사용 보안 회귀시험 |
| 15 | [AgentDojo, NeurIPS 2024](https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html) | 정상 업무와 공격을 함께 측정하는 동적 에이전트 평가 | 공격 성공률과 정상 업무 성공률을 같이 보는 안전성 하네스 |

## 4. 국내 공공기관·금융권 자료

### 4.1 KISA: 제로트러스트와 AI 보안

| 자료 | 상태·접근 | 적용 포인트 |
|---|---|---|
| [제로트러스트 가이드라인 2.0](https://www.kisa.or.kr/2060204/form?page=1&postSeq=18) | 공식 가이드, 무료 | 현재 OIDC·RBAC를 네트워크 위치와 무관한 지속적 신뢰평가로 확장하고 여섯 핵심 요소의 성숙도를 측정한다. |
| [AI 보안 위협 대응 매뉴얼](https://www.kisa.or.kr/401/form?lang_type=KO&postSeq=3712) | 2026 공식 매뉴얼, 무료 | 모델뿐 아니라 데이터·애플리케이션·인프라·공급망 위협을 시험 목록으로 전환한다. |
| [OT 환경 제로트러스트 적용 가이드](https://www.kisa.or.kr/402/form?postSeq=2566) | 공식 가이드, 무료 | 향후 산업·공공 인프라 연동 시 가용성, 실시간성, 안전을 우선하고 자동 차단을 더 엄격하게 제한한다. |
| [AI 안전·보안 규범 분석](https://www.kisa.or.kr/20301/form?lang_type=KO&postSeq=21) | 정책·기술 이슈 보고서, 무료 | 국내외 규범의 공통분모를 찾는 배경자료로 사용하고 의무 기준처럼 취급하지 않는다. |
| [DeepSeek 등 AI 보안 이슈 분석](https://www.kisa.or.kr/20301/form?page=1&postSeq=30) | 이슈 보고서, 무료 | 외부 모델 반입, 학습데이터·모델 출처, 해외 전송, 공급자 검토 질문을 구체화한다. |

프로젝트 적용:

- `principal/action/resource/context` 정책 입력에 사용자, 기기, 인증 강도, 데이터 민감도, 세션 위험을 포함한다.
- AI 자산대장에 모델 식별자, 공급자, 해시 또는 버전, 사용 목적, 데이터 범위, 배포 위치, 종료일을 기록한다.
- KISA 위협 항목을 `threat_id`, 공격 입력, 기대 차단점, 허용 가능한 실패, 증적 ID가 있는 회귀시험으로 바꾼다.

### 4.2 개인정보보호위원회: AI 개인정보 위험

| 자료 | 상태·접근 | 적용 포인트 |
|---|---|---|
| [AI 프라이버시 위험관리 모델](https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20799) | 공식 모델, 무료 | 개인정보 위험을 수명주기 전반에서 식별·측정·완화하고 결과를 기록한다. |
| [LLM 제공사업자 사전 실태점검 결과와 개선 권고](https://pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS074&mCode=C020010000&nttId=10027) | 감독기관 점검·권고, 무료 | 입력 데이터의 학습 이용, 보존기간, 국외 이전, 이용자 고지, 삭제와 옵트아웃을 공급자 계약 질문으로 바꾼다. |
| [가명정보 처리 가이드라인 2026.3](https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20877) | 공식 개정 가이드, 무료 | 실제 보안로그 반입 전 가명처리, 결합 가능성, 재식별 위험, 접근권한과 파기 절차를 확인한다. |
| [개인정보 영향평가 수행안내서와 AI 분야 평가항목](https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20848) | 공식 안내서, AI 항목 일부는 의견수렴 자료 | 공공기관 AI 도입 시 개인정보 영향평가 범위와 구체적인 평가기준을 확인한다. |

프로젝트 적용:

- 원본 로그, 정규화 이벤트, LLM 입력, 분석 결과마다 개인정보 포함 가능성과 보존기간을 따로 둔다.
- 프롬프트·응답을 무조건 장기 저장하지 않고, 운영 감사에 필요한 필드만 분리 보관한다.
- 삭제 요청이 원본, 파생 이벤트, 캐시, 평가 데이터, 백업까지 전달되는지 자동 시험한다.

### 4.3 NIA: 공공부문 도입과 데이터 품질

| 자료 | 상태·접근 | 적용 포인트 |
|---|---|---|
| [공공부문 AI 도입·활용 가이드](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=29526&cbIdx=37989) | 2026 공식 가이드, 무료 | 기획, 요구사항, 계약, 구축, 운영, 모니터링, 예산과 성과평가를 하나의 도입 절차로 본다. |
| [공공부문 초거대 AI 도입·활용 가이드 2.0 및 사례집](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=27985&cbIdx=99953) | 공식 가이드·110개 사례, 무료 | 자체 구축·민간 서비스·API 방식의 책임과 데이터 경계를 비교하는 데 쓴다. |
| [공공부문 AI·데이터분석 운영 사례](https://nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28925&cbIdx=27974) | 공식 사례·운영 가이드, 무료 | PoC 이후 운영조직, 품질 모니터링, 성과관리와 현업 책임을 설계한다. |
| [생성형 AI 윤리 가이드](https://nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=26195&cbIdx=39485&parentSeq=26195) | 공식 가이드, 무료 | 투명성, 책임, 편향, 저작권, 이용자 보호 항목을 서비스 고지와 검토 절차에 반영한다. |
| [AI 데이터 품질관리 가이드라인 v3.5](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28109&cbIdx=90549&parentSeq=28109) | 공식 가이드, 무료 | LLM·멀티모달·합성데이터까지 포함한 데이터 품질 차원과 검사 방식을 평가 데이터 관리에 적용한다. |
| [공공부문 SaaS 이용 가이드](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=26399&cbIdx=99835&parentSeq=26399) | 공식 가이드, 무료 | SaaS 책임 분담, 계약, 데이터 이전·회수, 서비스 종료 계획에 활용한다. |
| [AI 기본법 이행 지원 가이드라인 묶음](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28987&cbIdx=99835&parentSeq=28987) | 2026 공식 이행 자료, 무료 | 투명성, 안전성, 고영향 여부, 영향평가를 제품 요구사항과 기록 양식으로 연결한다. |

### 4.4 금융보안원: 금융 AI·클라우드·오픈소스

| 자료 | 상태·접근 | 적용 포인트 |
|---|---|---|
| [금융분야 AI 보안 가이드라인](https://www.fsec.or.kr/bbs/detail?bbsNo=11240&menuNo=69) | 공식 가이드, 무료 | 금융권 AI 수명주기의 데이터·모델·서비스 보안을 확인한다. |
| [금융분야 오픈소스 소프트웨어 활용·관리 안내서](https://www.fsec.or.kr/bbs/detail?bbsNo=11166&menuNo=222) | 공식 안내서, 무료 | 의존성 승인, 라이선스, 취약점, 유지보수 종료, SBOM 운영에 사용한다. |
| [금융분야 클라우드컴퓨팅서비스 이용 가이드 2025](https://www.fsec.or.kr/bbs/detail?bbsNo=11691&menuNo=222) | 공식 개정 가이드, 무료 | 책임공유, 중요도 평가, 계약, 접근통제, 백업, 종료·이전 계획을 점검한다. |
| [연구·개발 목적 망분리 예외 보안 해설서](https://www.fsec.or.kr/bbs/detail?bbsNo=11686&menuNo=222) | 공식 해설서, 무료 | 외부 모델·패키지를 쓰는 격리 개발환경과 반입·반출 승인, 기록을 설계한다. |
| [클라우드 보안관리 참고자료](https://www.fsec.or.kr/bbs/detail?bbsNo=11797&menuNo=69) | 공식 참고자료, 무료 | 8개 영역·47개 통제를 AWS 운영 점검표와 장애복구 훈련으로 전환한다. |

### 4.5 국내 법·인증 기준

| 자료 | 상태·접근 | 적용 포인트 |
|---|---|---|
| [인공지능기본법 제33조 고영향 AI 확인](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810895) | 시행 법령, 무료 | 서비스 제공 전 고영향 해당 여부를 기록하고 불명확하면 공식 확인 절차를 검토한다. |
| [인공지능기본법 제34조 사업자 책무](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810839) | 시행 법령, 무료 | 위험관리, 설명, 이용자 보호, 사람 감독, 안전성 문서 보관을 통제대장에 반영한다. |
| [ISMS-P 포털과 인증기준 자료실](https://isms.kisa.or.kr/ntcn/rcsrm/selectGnrlRcsrmList.do) | 공식 인증 기준·세부점검항목, 무료 | 2023 안내서는 발간시점 법령 기준이므로 최신 고시·점검항목과 함께 사용한다. |

국내 기준으로 우선 만들 문서는 `AI 서비스 범위서`, `고영향 여부 검토서`, `개인정보 데이터 흐름도`, `AI 자산대장`, `통제대장`, `공급자 질문지`, `사고대응·서비스 종료 계획`이다.

## 5. 해외 정부·공공기관 가이드

### 5.1 NIST: 조직 통제, 안전한 개발, AI 위험

| 자료 | 상태 | 프로젝트 적용 |
|---|---|---|
| [Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) | 최종, 무료 | Govern·Identify·Protect·Detect·Respond·Recover에 기능과 책임자를 배치한다. |
| [SP 800-53 Rev.5, Release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | 최종, 무료·OSCAL 제공 | 통제 선택과 기계 판독 가능한 증적 매핑의 기준으로 쓴다. |
| [SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | 최종, 무료 | 저장소 보호, 변경 검토, 취약점 대응, 출시 무결성을 SDLC에 넣는다. 1.2는 별도 초안이므로 혼동하지 않는다. |
| [SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) | 최종, 무료 | 생성형 AI·기반모델 개발자와 사용자의 공급망·데이터·모델·평가 관행을 추가한다. |
| [SP 800-63-4 Digital Identity](https://csrc.nist.gov/pubs/sp/800/63/4/final) | 2025 최종, 무료 | 인증 강도, 수명주기, 피싱 저항, 연합 인증을 OIDC 운영 기준에 반영한다. |
| [SP 800-92 Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) | 2006 최종, 무료 | 로그 관리 기본선이다. 최신 개정 [Rev.1](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd)은 **초기 공개초안**이므로 확정 기준처럼 인용하지 않는다. |
| [AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/) | 생활문서, 무료·CSV/JSON 제공 | Govern·Map·Measure·Manage의 제안 행동을 필요한 항목만 선택한다. AI RMF 1.0 자체가 개정 중임을 기록한다. |
| [AI 100-2e2025 Adversarial ML Taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) | 최종, 무료 | 공격 단계·공격자 능력·영향을 일관된 용어로 위협 모델에 넣는다. |
| [ARIA 평가 프로그램](https://ai-challenges.nist.gov/aria) | 공공 평가 프로그램, 무료 자료 | 모델시험, 레드팀, 현장시험의 세 층을 프로젝트 평가 계획에 적용한다. |
| [SP 800-204D DevSecOps 공급망](https://www.nist.gov/publications/strategies-integration-software-supply-chain-security-devsecops-cicd-pipelines) | 최종, 무료 | CI/CD에 SBOM, 출처, 증명, 아티팩트 검증을 결합한다. |

### 5.2 CISA·NSA: 제로트러스트, 로그, 공급망

| 자료 | 상태 | 프로젝트 적용 |
|---|---|---|
| [CISA Zero Trust Maturity Model v2](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf) | 최종, 무료 | KISA 2.0과 교차 매핑해 현재·목표 성숙도를 정하고 단계적 백로그를 만든다. |
| [NSA Zero Trust Implementation Guidelines](https://www.nsa.gov/Cybersecurity/ZIG/Primer/) | 2026 구현 포털, 무료 | 준비도·발견·구현 단계를 따라 제로트러스트 전환 순서와 증적을 만든다. |
| [NSA Visibility and Analytics Pillar](https://www.nsa.gov/Cybersecurity/ZIG/Pillars/Visibility-and-Analytics-Pillar/) | 공식 구현 지침, 무료 | 관련 활동 로깅, 중앙 분석, UEBA, 위협 인텔리전스, 동적 정책을 연결한다. |
| [CISA·국제기관 LOTL 탐지 지침](https://www.cisa.gov/sites/default/files/2024-02/Joint-Guidance-Identifying-and-Mitigating-LOTL_V3508c.pdf) | 공동 최종 지침, 무료 | 정상 도구를 악용하는 공격을 찾기 위해 중앙·대역외 로그와 행위 상관분석을 강화한다. |
| [CISA Secure by Demand](https://www.cisa.gov/sites/default/files/2024-08/SecureByDemandGuide_080624_508c.pdf) | 구매자 가이드, 무료 | 보안로그 기본 제공, 보존, SSO·MFA, 취약점 공개, 공급망 출처를 공급자 계약 질문으로 만든다. |
| [CISA SBOM Minimum Elements](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf) | 2025 최종 기준, 무료 | AI 소프트웨어·SaaS도 포함하는 최소 SBOM 필드, 자동화, 운영 관행을 요구한다. |
| [NIST Software Supply Chain Guidance](https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance) | 공식 자원 모음, 무료 | 공급자 보안, 코드 검증, SBOM, 오픈소스, 취약점 대응을 조달과 개발에 같이 적용한다. |
| [NSA 공동 AI Data Security Best Practices](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/) | 2025 공동 지침, 무료 | 데이터 출처, 서명, 신뢰 인프라, 공급망, 변조, 드리프트를 데이터 계약과 무결성 시험에 반영한다. |

### 5.3 영국·EU: 안전한 AI 개발, 보증, 규제 구현

| 자료 | 상태 | 프로젝트 적용 |
|---|---|---|
| [NCSC Secure AI System Development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) | 다국가 공동 지침, 무료 | 설계·개발·배포·운영 네 단계의 보안 검토표를 만든다. 한국 국가정보원도 지지기관에 포함된다. |
| [UK AI Cyber Security Code of Practice](https://www.gov.uk/government/publications/ai-cyber-security-code-of-practice) | 2025 정부 코드, 무료 | 13개 원칙을 AI 자산·공급망·데이터·모델·프롬프트·시험·업데이트·폐기 통제로 만든다. |
| [ETSI EN 304 223](https://www.etsi.org/newsroom/press-releases/2627-etsi-releases-world-leading-standard-for-securing-ai/) | 2026 유럽 표준 | 영국 코드에서 발전한 AI 사이버보안 기준이다. 조직별 적합성 평가 범위를 정할 때 사용한다. |
| [UK Introduction to AI Assurance](https://www.gov.uk/government/publications/introduction-to-ai-assurance) | 정부 가이드, 무료 | 영향평가·감사·성능시험·형식검증을 위험에 비례해 조합하고 보증 결과를 전달하는 법을 설계한다. |
| [UK Inspect AI](https://www.aisi.gov.uk/blog/open-sourcing-our-testing-framework-inspect) | 정부 오픈소스 평가 프레임워크 | 로컬 또는 허용된 모델에서 재현 가능한 데이터셋·도구·채점기 기반 평가를 만든다. |
| [ENISA Multilayer Framework for Good Cybersecurity Practices for AI](https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai) | 최종 보고서, 무료 | 기반·AI 수명주기·산업 맥락을 분리해 다층 통제를 설계한다. |
| [ENISA NIS2 Technical Implementation Guidance](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance) | 2025 v1.0, 무료 | 정책, 위험, 사고, 연속성, 공급망, 개발, 효과성 평가, 암호화, 접근·자산관리의 증거 예시를 활용한다. 적용 업종은 별도 확인한다. |
| [EU AI Act 공식 안내](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) | 시행 법령의 공식 안내, 무료 | EU 제공·배포 가능성이 생기면 위험 분류, 로그·문서, 사람 감독, 견고성·사이버보안 의무와 적용 일정을 최신 원문으로 다시 확인한다. |
| [EDPB Opinion 28/2024 on AI Models](https://www.edpb.europa.eu/documents/opinion-of-the-board-art-64/opinion-282024-on-certain-data-protection-aspects-related-to_en) | 공식 의견, 무료 | 모델의 익명성은 자동으로 가정하지 않고 사례별 평가, 적법 근거와 불법 처리의 후속 영향을 검토한다. |
| [CNIL AI·GDPR 개발 체크리스트](https://www.cnil.fr/en/ai-system-development-cnils-recommendations-to-comply-gdpr) | 감독기관 실무 가이드, 무료 | 목적, 법적 근거, 최소화, DPIA, 검증된 도구·모델, 재현 가능한 환경, 공격시험을 개발 게이트에 넣는다. |
| [ICO AI and Data Protection Risk Toolkit](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/artificial-intelligence/guidance-on-ai-and-data-protection/ai-and-data-protection-risk-toolkit/) | 감독기관 도구, 무료 | 개인정보 위험 문장과 완화 상태를 구조화한다. 현재 관련 영국 법 변화로 검토 중이라는 상태를 함께 기록한다. |

### 5.4 아시아·호주 공공 프레임워크

| 자료 | 상태 | 프로젝트 적용 |
|---|---|---|
| [싱가포르 IMDA Model AI Governance Framework·AI Verify](https://www.imda.gov.sg/About-IMDA/Research-and-Statistics/SGDigital/tech-pillars/Artificial-Intelligence) | 공식 프레임워크·오픈소스 도구 | 투명성, 설명가능성, 재현성, 안전성, 보안, 견고성, 공정성, 데이터 거버넌스를 기술시험과 절차점검으로 나눈다. |
| [IMDA Project Moonshot](https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/factsheets/2024/project-moonshot) | 공식 GenAI 시험 프로젝트 | 견고성, 사실성, 편향, 독성, 데이터 거버넌스 시험을 LLM 평가 후보로 쓴다. |
| [일본 METI·MIC AI Guidelines for Business v1.1](https://www.meti.go.jp/shingikai/mono_info_service/ai_shakai_jisso/20240419_report.html) | 2025판 공식 가이드, 영문 제공 | 경영진·개발자·제공자·이용자의 역할, 사람 중심, 안전, 공정, 개인정보, 투명성, 책임을 조직 RACI에 반영한다. |
| [호주 ASD Essential Eight Maturity Model FAQ](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model-faq) | 정부 성숙도 지침, 무료 | 자산, 패치, MFA, 권한, 백업과 이벤트 로그 수집·분석 주기를 기본 보안 위생에 적용한다. |

## 6. 국제표준

| 표준 | 원문 접근 | 사용할 부분 |
|---|---|---|
| [ISO/IEC 42001:2023](https://www.iso.org/standard/42001) | ISO 요약 무료, 전체 표준은 일반적으로 유료 | AI 관리체계의 정책, 목표, 역할, 영향, 수명주기, 지속 개선 |
| [ISO/IEC 23894:2023](https://www.iso.org/standard/77304.html) | 요약 무료, 전체 유료 | AI 위험 식별·분석·평가·처리와 모니터링 |
| [ISO/IEC 42005:2025](https://www.iso.org/standard/42005) | 요약 무료, 전체 유료 | AI 시스템 영향평가 과정과 문서화 |
| [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) | 요약 무료, 전체 유료 | 정보보호 관리체계와 위험기반 통제 운영 |
| [ISO/IEC 27035-1:2023](https://www.iso.org/standard/78973.html) | 요약 무료, 전체 유료 | 보안사고 관리 원칙과 준비 체계 |

ISO 인증이 현재 MVP의 선행조건은 아니다. 먼저 공개된 KISA·NIST·ENISA·CSA 자료로 통제와 증적 구조를 만들고, 실제 고객이 ISO 인증이나 계약상 적합성을 요구할 때 정식 원문과 전문가 검토를 확보하는 편이 효율적이다.

## 7. 기업·산업 실무 프레임워크

이 자료들은 법령이나 독립적인 성능 증거가 아니다. 다만 실제 통제, 위협 모델, 공급자 질문, 시험 케이스를 빠르게 설계하는 데 유용하다.

| 자료 | 강점 | 프로젝트 적용 |
|---|---|---|
| [Google Secure AI Framework](https://saif.google/secure-ai-framework) | 데이터·인프라·모델·애플리케이션 전체의 15개 AI 위험과 통제 | 데이터 중독, 모델 변조·유출, 비안전 출력, 에이전트의 비정상 조치를 자산별로 매핑한다. |
| [Microsoft AI Red Team 자료](https://learn.microsoft.com/en-us/security/ai-red-team/) | AI 위협 모델, 실패 분류, 레드팀 구축, PyRIT 실습 | 프롬프트·모델·도구 인터페이스를 공격하는 자동 회귀시험 설계에 사용한다. |
| [AWS Generative AI Security Scoping Matrix](https://docs.aws.amazon.com/whitepapers/latest/navigating-security-landscape-genai/navigating-security-landscape-genai.html) | 소비형 SaaS부터 자체 학습까지 다섯 범위의 책임 차이 | 현재 프로젝트를 사전학습 모델 기반 애플리케이션으로 분류하고 공급자·개발자 책임을 분리한다. AWS 배포를 정당화하는 자료로 오용하지 않는다. |
| [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) | 애플리케이션 공격 위험을 간결하게 분류 | 각 항목에 공격 입력, 기대 결과, 정책 차단, 로그 증적이 있는 테스트를 만든다. |
| [MITRE ATLAS](https://atlas.mitre.org/) | 실제 관찰·실증 기반 AI 공격 지식베이스 | 전통 IT는 ATT&CK, AI 구성요소는 ATLAS로 이중 매핑한다. |
| [Cloud Security Alliance AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) | 18개 영역·247개 통제와 ISO·NIST·EU 매핑, 기계판독 형식 | AI 고객·앱 제공자 관점의 통제 질문지와 감사 체크리스트를 만든다. 다운로드 절차가 필요할 수 있다. |
| [SLSA v1.2](https://slsa.dev/spec/v1.2/) | 소스·빌드 출처와 검증 가능한 증명 | 컨테이너 이미지, 모델 파일, 정책·규칙 번들의 출처와 서명을 검증한다. |
| [CISA Secure by Design](https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf) | 고객에게 보안 부담을 전가하지 않는 안전한 기본값 | 인증·감사·속도제한·최소권한을 선택형 유료 기능이 아닌 기본 제품 동작으로 유지한다. |

## 8. 추가로 참고할 논문

기존 [고도화 딥 리서치](deep-research-enterprise-secops.md)의 DeepLog, LogBERT, AIRTAG, SOCpilot, CaMeL, Cedar 연구에 아래 자료를 추가한다.

### 8.1 장기·다단계 공격 탐지와 사건 복원

| 논문 | 검증된 관찰 | 이 프로젝트에 주는 의미 |
|---|---|---|
| [HOLMES: Real-time APT Detection, USENIX Security 2019](https://arxiv.org/abs/1810.01594) | 의심스러운 정보 흐름을 상관분석하고 공격자의 행동을 고수준 그래프로 요약 | 개별 경보 점수보다 시간·프로세스·파일·네트워크의 인과 연결과 사건 요약이 중요하다. |
| [UNICORN, NDSS 2020](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24046-paper.pdf) | 장기 시스템 실행을 고정 크기 그래프 스케치로 요약해 저속 APT 이상행동을 탐지 | 무기한 원시 그래프만 쌓지 않고 장기 맥락을 보존하는 요약 구조가 필요하다. |
| [KAIROS, IEEE S&P 2024](https://spg.cs.ubc.ca/publication/2024-sp/) | 시간에 따른 provenance graph 변화를 학습하고 공격 흔적을 작은 요약 그래프로 재구성 | P1 상관분석의 목표를 `이상 점수`뿐 아니라 조사 가능한 공격 타임라인으로 둔다. |

이 연구들은 모두 풍부한 시스템 provenance를 전제로 한다. 현재 MVP의 간단한 이벤트에서 논문 성능이 그대로 재현된다고 가정하면 안 된다. 먼저 수집 가능한 엔터티와 인과관계의 품질을 측정해야 한다.

### 8.2 프롬프트 인젝션과 도구 사용 안전성

| 논문 | 검증된 관찰 | 이 프로젝트에 주는 의미 |
|---|---|---|
| [AgentDojo, NeurIPS 2024](https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html) | 97개 실제형 업무와 629개 보안 테스트에서 정상 유용성과 공격 저항을 함께 평가 | 향후 도구 호출을 추가할 때 공격 차단률만 높이고 정상 업무를 망치는 방어를 피한다. |
| [CaMeL, 2025](https://arxiv.org/abs/2503.18813) | 신뢰된 제어 흐름과 비신뢰 데이터를 분리하고 capability로 정보 흐름을 제한 | 이벤트 텍스트가 조치를 지시할 수 없도록 데이터와 명령 경계를 구조적으로 분리한다. |
| [CyberSecEval 2](https://arxiv.org/abs/2404.13161) | 프롬프트 인젝션과 코드·사이버 능력을 포함한 재현 가능한 평가 묶음 | 프로젝트 형식으로 변환한 고정 공격 회귀세트를 만든다. |

### 8.3 평가 데이터의 현실성과 재현성

| 논문·자원 | 관찰 | 사용법 |
|---|---|---|
| [Are public intrusion datasets fit for purpose?, Computers & Security 2020](https://doi.org/10.1016/j.cose.2020.102022) | 공개 침입 데이터는 현실성·대표성·출처 설명이 불균일해 모델 결과를 왜곡할 수 있음 | 단일 공개 데이터의 높은 F1을 운영 성능으로 홍보하지 않는다. 여러 소스와 시간순 분할, 데이터 카드를 사용한다. |
| [SOCBED, ACSAC 2021](https://publica.fraunhofer.de/entities/publication/ec8a756a-cd78-4efd-86fb-071bd7b97a85) | 일반 장비에서 재현·수정 가능한 기업형 침입 실험과 로그 생성 | 비용 없는 Docker·가상 환경에서 다단계 공격 로그를 생성하는 P1 실험 후보로 쓴다. |
| [Loghub, ISSRE 2023](https://github.com/logpai/loghub) | HDFS·BGL 등 여러 실제 시스템 로그와 벤치마크를 공개 | 파서·정규화·이상탐지 비교에 사용하되 저장소의 연구·학술 사용 조건과 개별 데이터 출처를 확인한다. |
| [Loghub-2.0 / 대규모 로그 파싱 평가](https://arxiv.org/abs/2308.10828) | 더 크고 현실적인 주석 데이터로 파서 일반화 한계를 비교 | OCSF 변환 전 로그 파싱기의 공급자·버전 변화 회귀시험에 사용한다. |

## 9. 무료로 사용할 수 있는 평가 데이터·도구

| 자원 | 적합한 시험 | 주의점 |
|---|---|---|
| [LANL Cyber Security Data Sets](https://csr.lanl.gov/data/) | 인증·호스트·네트워크 상관분석, 엔터티 행동 | 대규모이므로 작은 기간·필드 표본부터 사용하고 이용 조건을 확인한다. |
| [DARPA Transparent Computing](https://www.darpa.mil/research/programs/transparent-computing) | provenance 기반 APT 탐지·인과관계 연구의 구조와 데이터 계보 | 프로그램은 종료돼 참고용이며, 개별 데이터셋의 배포 위치·라이선스를 별도 확인한다. |
| [Loghub](https://github.com/logpai/loghub) | 로그 파싱, 데이터 품질, 이상탐지 기준선 | 보안 공격 데이터만 있는 것이 아니며 생산 재배포 권리와는 별개다. |
| [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) | Windows 공격 이벤트, ATT&CK 탐지 검증 | 데이터별 설명과 공격 절차를 확인하고 실제 시스템 공격용으로 사용하지 않는다. |
| [Atomic Red Team](https://www.atomicredteam.io/) | ATT&CK 기법별 탐지 검증 | 승인된 격리 환경에서만 실행하고 기본은 공개 로그 재생으로 시작한다. |
| [MITRE CALDERA](https://www.mitre.org/our-impact/intellectual-property/caldera) | 다단계 공격·대응 훈련 | 외부와 분리된 실험 대상과 명시적 범위가 필요하다. |
| [UK Inspect AI](https://www.aisi.gov.uk/blog/open-sourcing-our-testing-framework-inspect) | LLM 데이터셋·도구·채점기 기반 평가 | 정부가 공개한 평가 프레임워크의 데이터셋·도구·채점기 구조를 참고한다. |
| [AI Verify](https://www.imda.gov.sg/About-IMDA/Research-and-Statistics/SGDigital/tech-pillars/Artificial-Intelligence) | AI 거버넌스 절차점검과 기술시험 보고 | 모든 위험 부재를 보증하는 인증으로 해석하지 않는다. |

## 10. 자료를 프로젝트 산출물로 바꾸는 교차표

| 산출물 | 핵심 근거 | 프로젝트에 추가할 내용 | 자동 확인 |
|---|---|---|---|
| `control-register` | ISMS-P, NIST 800-53, ENISA NIS2, CSA AICM | 통제 ID, 출처, 소유자, 구현, 증적, 예외, 만료일 | 필수 필드·만료 예외·고아 통제 검사 |
| `ai-system-card` | AI 기본법, NIST AI RMF, NIA, UK Code | 목적, 금지용도, 모델·데이터·성능 한계, 사람 감독 | 버전 변경 시 재승인 여부 검사 |
| `data-inventory` | PIPC, EDPB, CNIL, NSA AI Data Security | 출처, 적법성, 민감도, 위치, 보존, 삭제, 파생물 | 보존 만료·삭제 전파·출처 해시 시험 |
| `supplier-questionnaire` | CISA Secure by Demand, FSI Cloud, NIA SaaS | SSO, 로그, 보존, 사고 통지, 하위처리자, 종료·회수, SBOM | 답변 누락과 고위험 예외 차단 |
| `threat-model` | KISA AI 매뉴얼, NIST AI 100-2, ATLAS, OWASP, SAIF | 자산·신뢰경계·공격자·위협·통제·잔여위험 | 위협별 최소 한 개 예방·탐지 시험 |
| `secure-development-plan` | SSDF, SSDF 218A, NCSC, SLSA | 검토, 의존성, 비밀, 빌드 출처, 서명, 출시 게이트 | SBOM·취약점·출처·테스트 결과 검증 |
| `evaluation-plan` | AI Verify, ARIA, Inspect, AgentDojo | 모델시험·레드팀·현장시험, 정상/공격 동시 지표 | 고정 데이터·시드·버전·채점기 재현성 |
| `logging-standard` | NSA 가시성, CISA LOTL, NIST 800-92 | 필수 이벤트, 시간동기, 무결성, 보존, 접근, 결손 경보 | 로그 누락·순서·해시 체인·테넌트 격리 |
| `incident-playbook` | NIST 800-61r3, ISO 27035, UK Code | 분류, 담당자, 승인, 봉쇄, 복구, 통지, 사후검토 | 테이블톱·장애주입·증적 묶음 생성 |
| `zero-trust-profile` | KISA ZT 2.0, CISA ZTMM, NSA ZIG | 현재 성숙도, 목표, 신뢰 신호, 정책 결정·집행 | 인증·기기·테넌트·정책 회귀시험 |

## 11. 다음 개발 단계에 바로 적용할 일

### P0: 문서를 코드와 시험에 연결

1. ~~통제대장 스키마를 만들고 KISA·ISMS-P·NIST·OWASP·ATLAS의 핵심 항목부터 등록한다.~~ 0.8.0 완료
2. ~~각 통제를 `implemented`, `partially_implemented`, `planned`, `not_applicable`로 상태화하고 근거 없는 `implemented`를 금지한다.~~ 0.8.0 완료
3. ~~기존 자동 테스트가 어떤 통제를 입증하는지 역방향 링크한다.~~ 0.8.0 1차 완료
4. 모델·프롬프트·규칙·정책·데이터셋 버전이 분석 결과와 평가 보고서에 남도록 한다. 규칙집·OCSF 매핑은 0.9.0, 공개 데이터셋 커밋·라이선스·해시는 0.10.0 1차 완료했으며 모델·프롬프트·정책 계보는 계속 진행한다.
5. 개인정보 보존·삭제와 공급자 종료·회수 시나리오를 테스트에 추가한다.

### P1: 무료 로컬 보증 실험

1. ~~내부 합성 이벤트와 공개 공격·정상 표본의 OCSF 1.9.0·Sigma 재생, 필드 매핑률과 파싱 성공률을 연결한다.~~ 0.11.0에서 12건·2개 규칙 기준 1차 완료. 다음으로 나머지 4개 규칙의 공개 양성·음성 표본과 대용량 처리량을 측정한다.
2. ~~여러 이벤트를 하나의 사건으로 묶고 타임라인·근거 ID를 생성한다.~~ 0.10.0 1차 완료, 0.12.0 다중 시간창·엔터티 그래프 완료, 0.13.0 데이터셋 단위 사건·구조 품질 게이트 완료. 다음으로 독립 정답셋에서 엔터티 연결 단위 정확도를 측정한다.
3. OWASP·ATLAS·AgentDojo 유형의 프롬프트 인젝션, 데이터 유출, 과도한 권한 테스트를 로컬 회귀세트로 만든다.
4. 허용·금지 대응계획을 생성해 정책 엔진의 차단률과 정상계획 보존률을 함께 측정한다.
5. 위 결과를 통제별 증적 묶음으로 자동 내보낸다.

### P2: 실제 기관·기업 실증 전

1. 고객 업종과 데이터에 따라 국내 법령, ISMS-P, 금융·공공 가이드를 다시 스코핑한다.
2. IdP, SIEM, DLP, 티켓 시스템과의 연동 책임·장애 모드를 정의한다.
3. 독립 보안검토, 개인정보 영향 검토, 복구훈련, 공급자 종료훈련을 수행한다.
4. 규제·표준·모델 변경을 분기별로 확인하고 통제 매핑의 영향을 기록한다.

## 12. 현재 프로젝트에 대한 권고

현 단계에서 가장 가치가 큰 다음 구현은 `통제대장 + 자료 출처 + 자동 시험 + 증적 묶음`이다. 이미 인증, 테넌트 격리, 감사 해시 체인, 정책 미리보기, 사람 검토가 있으므로 새 프레임워크를 많이 도입하는 것보다 기존 기능이 어떤 공공·기업 요구사항을 충족하는지 검증 가능하게 만드는 편이 우선이다.

OCSF 정규화와 Sigma 합성 재생까지 완료했으므로 다음 순서는 `공개 로그 재생 + 파서 품질 측정 + 사건 상관분석`이다. LLM 자율 대응은 이 통제와 보증 체계가 완성되고 실제 조직 데이터로 검증되기 전까지 계속 비활성화해야 한다.
