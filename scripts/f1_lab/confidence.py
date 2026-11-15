"""Exact binomial reference bounds; they do not make authored variants independent.

Reference: NIST e-Handbook 7.2.4.1, exact binomial intervals.
https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm
"""

import math


def _tail(start, end, n, p):
    if start > end:
        return 0.0
    if p == 0:
        return float(start <= 0 <= end)
    if p == 1:
        return float(start <= n <= end)
    terms = [math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1)
             + k*math.log(p)+(n-k)*math.log1p(-p) for k in range(start, end+1)]
    largest = max(terms)
    return min(1.0, math.exp(largest)*math.fsum(math.exp(value-largest) for value in terms))


def exact_interval(successes, trials, *, confidence=.95):
    if (type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials <= 10000
            or not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
            or not math.isfinite(confidence) or not 0 < confidence < 1):
        raise ValueError('binomial_reference_parameters')
    if trials == 0:
        return {'lower': None, 'upper': None, 'successes': successes, 'trials': trials, 'confidence': confidence}
    tail = (1-confidence)/2
    if successes == 0:
        lower = 0.0
    elif successes == trials:
        lower = tail**(1/trials)
    else:
        left, right = 0.0, 1.0
        for _ in range(64):
            middle = (left+right)/2
            if _tail(successes, trials, trials, middle) < tail:
                left = middle
            else:
                right = middle
        lower = (left+right)/2
    if successes == trials:
        upper = 1.0
    elif successes == 0:
        upper = -math.expm1(math.log(tail)/trials)
    else:
        left, right = 0.0, 1.0
        for _ in range(64):
            middle = (left+right)/2
            if _tail(0, successes, trials, middle) > tail:
                left = middle
            else:
                right = middle
        upper = (left+right)/2
    return {'lower': lower, 'upper': upper, 'successes': successes, 'trials': trials, 'confidence': confidence}


def independent_trial_reference(counts, *, assumptions_verified=False):
    if set(counts) != {'tp', 'fp', 'fn', 'tn'} or any(type(v) is not int or v < 0 for v in counts.values()):
        raise ValueError('binomial_reference_counts')
    if type(assumptions_verified) is not bool:
        raise ValueError('binomial_reference_assumption_flag')
    # Three marginal two-sided intervals use Bonferroni alpha/3 for a joint
    # nominal 95% reference, conditional on genuinely independent trials.
    marginal_confidence = 1-.05/3
    precision = exact_interval(counts['tp'], counts['tp']+counts['fp'], confidence=marginal_confidence)
    recall = exact_interval(counts['tp'], counts['tp']+counts['fn'], confidence=marginal_confidence)
    fpr = exact_interval(counts['fp'], counts['fp']+counts['tn'], confidence=marginal_confidence)
    p, r = precision['lower'], recall['lower']
    f1_lower = None if p is None or r is None else 2*p*r/(p+r) if p+r else 0.0
    target_bounds = (p is not None and p >= .95 and r is not None and r >= .95
                     and f1_lower is not None and f1_lower >= .95 and fpr['upper'] is not None and fpr['upper'] <= .05)
    return {'method': 'exact-binomial-marginals-bonferroni-three-hypothetical-independent-trials',
        'precision': precision, 'recall': recall, 'false_positive_rate': fpr,
        'f1_lower_from_precision_recall': f1_lower, 'joint_nominal_confidence_if_assumptions_hold': .95,
        'assumptions_verified': assumptions_verified,
        'data_eligibility_review': 'not_performed_by_this_math_function',
        'bounds_meet_targets_under_hypothetical_independence': target_bounds,
        # A caller flag cannot substitute for independent data/label review.
        'conditional_bounds_and_caller_assumption_pass': bool(assumptions_verified and target_bounds),
        'population_target_supported': False,
        'limits': ['Only a reference if independent fixed-distribution trials are justified.',
                   'Author-labeled family variants and selected cases do not establish those assumptions.',
                   'This does not replace grouped uncertainty, independent review or an unseen evaluation.'],
        'primary_source': 'https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm'}
