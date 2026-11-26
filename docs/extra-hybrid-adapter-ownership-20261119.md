# 주입한 Hybrid adapter의 선택과 소유권

2026-11-19 · extra · 로컬 무료 시험, 업로드·CI·병합 없음.

Hybrid의 `llm or OpenAIAnalyzer(settings)`는 명시적으로 주입한 adapter라도 `__bool__()`이False이거나 `__len__()`이0이면 새 OpenAIAnalyzer를 생성했다. 요청하지 않은 client 생성과 주입 adapter 무시가 발생하며, 새로 추가한 `_owns_llm = llm is None`과도 실제 생성 조건이 달랐다. 원래부터 있던 선택 표현에서 이 두 사례를 재현했고 수정 전2건 모두 실패했다. 실제 외부 client를 만들지 않도록 factory를 로컬 stub으로 바꿔 시험했다.

선택을 `OpenAIAnalyzer(settings) if llm is None else llm`으로 바꿨다. 명시적None만 자체 client를 만들며, 주입한 객체의 truthiness에 따라 다른 client로 대체하지 않는다. 실제 선택과 `_owns_llm`의 기준이 일치한다. 외부 주입 adapter는 그대로 분석에 쓰고 Hybrid가 임의로 닫지 않는다.

신규2건은 bool/length 두 방식의 falsey adapter에 대해 추가 생성0회, 실제 주입 adapter 분석1회, 외부 소유 client close0회를 확인한다. 기존 평가 client 종료·SDK caller 경계·Hybrid 판정 회귀와 묶어 **Windows51건 통과**했다. [수정 전/후 XML·소스 지문](infrastructure-results/extra-hybrid-adapter-ownership-20261119.json).

```sh
python -m pytest tests/test_hybrid_adapter_ownership.py tests/test_evaluation_runtime.py tests/test_hybrid_analyzer.py tests/test_caller_sdk_retry.py -q
```

기존 규칙/LLM의 판정식이나 prompt, 평가 원본/정답/결과와 기존 F1·오탐·미탐은 바꾸지 않았다. 새 유료 모델 평가가 아니며 과금/AWS 호출0이다. 실제8시간 soak도 시작하지 않았다. 전체 Windows/Linux 로컬 회귀는 별도 결과로 정리한다.
