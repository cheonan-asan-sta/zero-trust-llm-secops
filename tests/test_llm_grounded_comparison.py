import pytest

from scripts.compare_llm_grounded import compare_rows


def row(identity, truth, prediction):
    return {"id": identity, "truth": truth, "prediction": prediction}


def test_equal_total_recall_cannot_hide_a_lost_previously_detected_threat():
    before = [row("a", True, True), row("b", True, False), row("c", False, True)]
    after = [row("a", True, False), row("b", True, True), row("c", False, False)]
    result = compare_rows(before, after)
    assert result["reference"]["FN"] == result["candidate"]["FN"] == 1
    assert result["FP_reduced"] and not result["no_lost_detections"]
    assert result["lost_TP_ids"] == ["a"]


def test_abstentions_never_count_as_corrections_or_retained_detections():
    before = [row("a", True, True), row("b", False, True), row("c", False, False)]
    after = [row("a", True, None), row("b", False, None), row("c", False, None)]
    result = compare_rows(before, after)
    assert result["corrected_FP_ids"] == [] and result["new_FP_ids"] == ["c"]
    assert not result["no_lost_detections"] and not result["FP_not_increased"]


@pytest.mark.parametrize(
    "after", [[], [row("b", True, True)], [row("a", True, True), row("a", True, True)]]
)
def test_dropped_replaced_or_duplicated_cases_cannot_pass_the_gate(after):
    with pytest.raises(ValueError):
        compare_rows([row("a", True, True)], after)


def test_changed_labels_cannot_pass_the_gate():
    with pytest.raises(ValueError, match="truth_mismatch"):
        compare_rows([row("a", True, True)], [row("a", False, False)])


def test_true_improvement_preserves_detected_threats_and_corrects_only_normal_rows():
    before = [row("a", True, True), row("b", False, None)]
    after = [row("a", True, True), row("b", False, False)]
    result = compare_rows(before, after)
    assert result["no_lost_detections"] and result["FP_reduced"]
    assert result["corrected_FP_ids"] == ["b"] and result["candidate"]["F1"] == 1
