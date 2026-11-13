"""Persist a web verification attempt before acknowledging an advisory result."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from scripts.f1_lab.operation_context import core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.web_evidence_ledger import WebEvidenceLedger, bounded, require
from scripts.f1_lab.web_residual import ACCESS, INTRINSIC_NAMES
from scripts.f1_lab.web_verified_context import VerifiedWebRisk, WebRequest, digest, digest_raw


@dataclass(frozen=True)
class DurableWebDecision(OperationDecision):
    evidence_state: str = 'baseline_only'
    storage_state: str = 'recorded'
    verified_adverse: bool = False
    journal_head_sha256: str | None = None


class DurableWebRisk:
    def __init__(self, verified, ledger):
        require(isinstance(verified,VerifiedWebRisk) and isinstance(ledger,WebEvidenceLedger)
                and verified.bridge is not None,'web_durable_configuration')
        self.verified, self.ledger = verified,ledger

    @bounded
    def decide(self, request, features, case_id, context=None, evidence=None, *, nonce=None, bundle=None,
               raw_line=None, principal=None, now=None):
        request = WebRequest.model_validate(request.model_dump())
        self.ledger._identity(request,principal)
        now = self.ledger._now(datetime.now(UTC) if now is None else now)
        require(request.case_id == case_id and isinstance(raw_line,str)
                and digest_raw(raw_line) == request.raw_line_sha256, 'web_durable_request_binding')
        match = ACCESS.fullmatch(raw_line.rstrip('\r\n'))
        require(match is not None and digest_raw(match['target']) == request.target_sha256
                and raw_line[:match.start('target')].rsplit('"',1)[-1].strip() == request.method,
                'web_durable_target_binding')
        intrinsic = core_features(raw_line)
        require(all(features[name] == intrinsic[name] for name in INTRINSIC_NAMES), 'web_durable_feature_binding')
        before = self.verified.baseline.decide(features,case_id,context,evidence)
        require(nonce is None or isinstance(nonce,str) and len(nonce) == 64 and set(nonce) <= set('0123456789abcdef'),
                'web_durable_nonce')
        nonce_sha = digest(['baseline',request.model_dump(mode='json')]) if nonce is None else digest_raw(nonce)
        with self.verified.bridge.lock:
            challenge = self.verified.bridge.pending.get(nonce) if nonce is not None else None
            deadline = challenge.expires_at if challenge is not None else now+timedelta(seconds=30)
            if challenge is not None:
                require(digest(challenge.request.model_dump(mode='json')) == digest(request.model_dump(mode='json'))
                        and challenge.owner == principal.subject,'web_durable_challenge_binding')
            attempt = self.ledger.begin(request,principal,nonce_sha,before,deadline=deadline,now=now)
            result = before
            if not attempt.duplicate:
                result = self.verified.decide(features,case_id,context,evidence,nonce=nonce,bundle=bundle,
                    raw_line=raw_line,principal=principal,now=now)
                # No successful acknowledgement before this result is committed
                # and published by the authenticated journal witness.
                self.ledger.finish(request,principal,attempt,result,now=now)
            summary = self.ledger.summary(request,principal,now=now)
        require(summary is not None,'web_durable_summary_missing')
        pending = summary['pending_attempts'] > 0
        state = ('retained_adverse' if summary['verified_adverse'] else 'verification_pending' if pending
                 else 'interrupted_review' if summary['interrupted'] else 'recorded_history')
        if not attempt.duplicate and not summary['verified_adverse']:
            state = getattr(result,'evidence_state','baseline_only')
        elif not attempt.duplicate and getattr(result,'evidence_state',None) == 'adverse':
            state = 'adverse'
        return DurableWebDecision(before.baseline_score,max(before.score,result.score,summary['score']),
            before.alert or result.alert or summary['alert'], before.review or result.review or summary['review'],
            'web_durable_adverse_retained' if summary['verified_adverse'] else result.reason,
            evidence_state=state,storage_state='pending' if pending else 'duplicate' if attempt.duplicate else 'recorded',
            verified_adverse=summary['verified_adverse'],journal_head_sha256=summary['journal_head_sha256'])
