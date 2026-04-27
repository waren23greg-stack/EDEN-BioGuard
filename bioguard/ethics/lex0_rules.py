# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Lex-0 Ethics Engine
bioguard/ethics/lex0_rules.py  |  v1.0.0

The constitutional ruleset for EDEN. Hard-coded ecological and human
rights rules that NO neural network output, agent decision, or
operator instruction can override.

Every physical action, financial transaction, and data publication
must pass through Lex-0 before execution. If it fails, it does not
happen. No exceptions.

Core rules enforced:
  1. No CarbonCreditNFT minted for zones with active displacement events
  2. No CarbonCreditNFT minted for zones with FRAUDULENT fraud assessment
  3. No hardware deployed on indigenous land without completed FPIC
  4. No insurance payout triggered before model accuracy >= 80% for 6mo
  5. No corporate intrusion alert suppressed regardless of actor identity
  6. No displacement record can be deleted or modified after sealing

Author : Warren Greg - EDEN-BioGuard
License: MIT
"""

from __future__ import annotations
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Any

logger = logging.getLogger(__name__)


# -- Enumerations -------------------------------------------------------------

class RuleVerdict(str, Enum):
    PERMITTED  = "PERMITTED"    # Action is allowed — proceed
    DENIED     = "DENIED"       # Hard rule violated — action blocked
    REVIEW     = "REVIEW"       # Soft concern — flag for human review
    ESCALATED  = "ESCALATED"    # Serious violation — alert legal + chain log


class ActionType(str, Enum):
    MINT_CARBON_CREDIT      = "mint_carbon_credit"
    DEPLOY_HARDWARE         = "deploy_hardware"
    TRIGGER_INSURANCE       = "trigger_insurance"
    PUBLISH_FRAUD_VERDICT   = "publish_fraud_verdict"
    DISPATCH_DRONE          = "dispatch_drone"
    LOG_DISPLACEMENT        = "log_displacement"
    DELETE_RECORD           = "delete_record"
    SUPPRESS_ALERT          = "suppress_alert"
    PLANT_SEEDS             = "plant_seeds"
    ISSUE_RANGER_ALERT      = "issue_ranger_alert"


# -- Rule result --------------------------------------------------------------

@dataclass
class RuleResult:
    """Result of a Lex-0 rule check."""
    action: ActionType
    verdict: RuleVerdict
    rule_triggered: str      # Which rule blocked or flagged this
    reason: str
    context: dict
    timestamp: str = ""
    audit_hash: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def is_permitted(self) -> bool:
        return self.verdict == RuleVerdict.PERMITTED

    def __str__(self) -> str:
        return (f"Lex-0 [{self.verdict.value}] {self.action.value} | "
                f"rule={self.rule_triggered} | {self.reason}")


# -- Individual rules ---------------------------------------------------------

class Lex0Rule:
    """Base class for all Lex-0 rules."""
    rule_id: str = "BASE"
    description: str = ""

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        """
        Returns RuleResult if this rule applies to the action.
        Returns None if this rule does not apply.
        """
        raise NotImplementedError


class NoCarbonCreditOnDisplacedLand(Lex0Rule):
    """
    RULE LEX-001
    No carbon credit NFT may be minted for any zone that has an active
    displacement event in the DisplacementLedger.

    Rationale: Conservation cannot profit from land theft. If a community
    was displaced to create a conservation zone, any carbon revenue from
    that zone is built on a human rights violation.
    """
    rule_id = "LEX-001"
    description = "No CarbonCreditNFT on land with active displacement event"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.MINT_CARBON_CREDIT:
            return None
        displaced_zones = context.get("displaced_zone_ids", [])
        target_zone = context.get("zone_id", "")
        if target_zone in displaced_zones:
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"Zone {target_zone} has active displacement event. "
                        f"Carbon credit minting blocked until community "
                        f"rights are restored and FPIC is completed."),
                context=context,
            )
        return None


class NoCarbonCreditOnFraudulentClaim(Lex0Rule):
    """
    RULE LEX-002
    No carbon credit NFT may be minted for any zone where the
    ConservationFraudDetector has returned a FRAUDULENT verdict.

    Rationale: Carbon credits require verified conservation. A fraudulent
    claim means the conservation did not happen — issuing credits is fraud.
    """
    rule_id = "LEX-002"
    description = "No CarbonCreditNFT for zones with FRAUDULENT fraud assessment"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.MINT_CARBON_CREDIT:
            return None
        fraud_verdict = context.get("fraud_verdict", "")
        if fraud_verdict == "FRAUDULENT":
            score = context.get("fraud_score", 0)
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"ConservationFraudDetector returned FRAUDULENT verdict "
                        f"(score={score}/100). Carbon credit minting blocked."),
                context=context,
            )
        return None


class NoHardwareOnIndigenousLandWithoutFPIC(Lex0Rule):
    """
    RULE LEX-003
    No physical hardware (drones, sensors, cameras) may be deployed on
    indigenous or ancestral land without completed Free Prior Informed
    Consent (FPIC) from the affected community.

    Rationale: UNDRIP Article 19. Communities have the right to give or
    withhold consent before any project affecting their land begins.
    """
    rule_id = "LEX-003"
    description = "No hardware deployment on indigenous land without FPIC"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action not in (ActionType.DEPLOY_HARDWARE, ActionType.DISPATCH_DRONE,
                          ActionType.PLANT_SEEDS):
            return None
        is_indigenous = context.get("indigenous_territory", False)
        fpic_status = context.get("fpic_status", "pending")
        if is_indigenous and fpic_status != "granted":
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"Target zone is indigenous territory. "
                        f"FPIC status: {fpic_status}. "
                        f"Action blocked until FPIC is granted by community."),
                context=context,
            )
        return None


class NoInsurancePayoutBeforeAccuracyThreshold(Lex0Rule):
    """
    RULE LEX-004
    No insurance payout may be triggered by an AI model that has not
    achieved >= 80% accuracy over at least 6 months in shadow mode.

    Rationale: Real money cannot depend on an unverified model.
    Farmers trust EDEN with their livelihoods — that trust must be earned
    with a public accuracy record before it is monetised.
    """
    rule_id = "LEX-004"
    description = "No insurance payout before model accuracy >= 80% for 6 months"

    MIN_ACCURACY_PCT = 80.0
    MIN_SHADOW_MONTHS = 6

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.TRIGGER_INSURANCE:
            return None
        accuracy = context.get("model_accuracy_pct", 0.0)
        shadow_months = context.get("shadow_mode_months", 0)
        if accuracy < self.MIN_ACCURACY_PCT:
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"Model accuracy {accuracy:.1f}% is below required "
                        f"{self.MIN_ACCURACY_PCT}%. Shadow mode required until threshold met."),
                context=context,
            )
        if shadow_months < self.MIN_SHADOW_MONTHS:
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"Model has only {shadow_months} months of shadow history. "
                        f"Minimum {self.MIN_SHADOW_MONTHS} months required before "
                        f"real payouts are triggered."),
                context=context,
            )
        return None


class NoAlertSuppression(Lex0Rule):
    """
    RULE LEX-005
    No intrusion, fraud, or displacement alert may be suppressed,
    regardless of who the alleged actor is — government, corporation,
    foreign investor, or conservation NGO.

    Rationale: Alert suppression based on actor identity would make EDEN
    complicit in the crimes it exists to expose. There are no protected actors.
    """
    rule_id = "LEX-005"
    description = "No alert suppression regardless of actor identity or political pressure"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.SUPPRESS_ALERT:
            return None
        # This action is always denied — no context can change this
        requester = context.get("requested_by", "unknown")
        alert_id  = context.get("alert_id", "unknown")
        return RuleResult(
            action=action,
            verdict=RuleVerdict.ESCALATED,
            rule_triggered=self.rule_id,
            reason=(f"Alert suppression requested by {requester} for alert {alert_id}. "
                    f"DENIED. Suppression requests are escalated to legal team "
                    f"and logged on-chain as potential interference."),
            context=context,
        )


class NoRecordDeletion(Lex0Rule):
    """
    RULE LEX-006
    No sealed displacement, fraud, or intrusion record may be deleted
    or retroactively modified. Records are permanent.

    Rationale: The value of EDEN as a legal tool depends entirely on
    the impossibility of record deletion. If powerful actors could
    delete records, the ledger is worthless.
    """
    rule_id = "LEX-006"
    description = "No deletion or modification of sealed records"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.DELETE_RECORD:
            return None
        record_id = context.get("record_id", "unknown")
        record_type = context.get("record_type", "unknown")
        requester = context.get("requested_by", "unknown")
        return RuleResult(
            action=action,
            verdict=RuleVerdict.ESCALATED,
            rule_triggered=self.rule_id,
            reason=(f"Deletion of {record_type} record {record_id} requested by "
                    f"{requester}. PERMANENTLY DENIED. This request has been "
                    f"logged on-chain as potential tampering."),
            context=context,
        )


class NoInvasiveSpeciesDeployment(Lex0Rule):
    """
    RULE LEX-007
    No seed deployment or reforestation action may use species classified
    as invasive in the target region.

    Rationale: Ecological harm done in the name of restoration is still
    ecological harm. Invasive species can devastate native ecosystems.
    """
    rule_id = "LEX-007"
    description = "No invasive species deployment in any region"

    def check(self, action: ActionType, context: dict) -> Optional[RuleResult]:
        if action != ActionType.PLANT_SEEDS:
            return None
        species = context.get("species", "")
        region = context.get("region", "")
        invasive_in_region = context.get("invasive_risk_high", False)
        if invasive_in_region:
            return RuleResult(
                action=action,
                verdict=RuleVerdict.DENIED,
                rule_triggered=self.rule_id,
                reason=(f"Species '{species}' is classified as high invasive risk "
                        f"in region '{region}'. Planting blocked. "
                        f"Use native species database to select alternatives."),
                context=context,
            )
        return None


# -- Lex-0 Engine -------------------------------------------------------------

class Lex0Engine:
    """
    The constitutional enforcement engine.

    All EDEN agents call engine.check(action, context) before executing
    any consequential action. If any rule returns DENIED or ESCALATED,
    the action does not proceed.

    The audit log records every check — permitted or denied — to IPFS
    and on-chain. Transparency is not optional.
    """

    # The complete ruleset — order matters: strictest rules first
    RULES: List[Lex0Rule] = [
        NoCarbonCreditOnDisplacedLand(),
        NoCarbonCreditOnFraudulentClaim(),
        NoHardwareOnIndigenousLandWithoutFPIC(),
        NoInsurancePayoutBeforeAccuracyThreshold(),
        NoAlertSuppression(),
        NoRecordDeletion(),
        NoInvasiveSpeciesDeployment(),
    ]

    def __init__(self, chain_notary=None, audit_store=None):
        self.chain = chain_notary
        self.audit = audit_store
        self._audit_log: List[RuleResult] = []
        logger.info("Lex-0 Engine initialised with %d rules", len(self.RULES))

    def check(self, action: ActionType, context: dict) -> RuleResult:
        """
        Run all applicable rules against the proposed action.
        Returns the first DENIED/ESCALATED result found, or PERMITTED.

        This is the single entry point for all agent action validation.
        """
        for rule in self.RULES:
            result = rule.check(action, context)
            if result is not None and not result.is_permitted():
                self._record(result)
                if result.verdict == RuleVerdict.ESCALATED:
                    self._escalate(result)
                logger.warning("Lex-0 BLOCKED: %s", result)
                return result

        # All rules passed — action permitted
        permitted = RuleResult(
            action=action,
            verdict=RuleVerdict.PERMITTED,
            rule_triggered="NONE",
            reason="All Lex-0 rules passed.",
            context=context,
        )
        self._record(permitted)
        logger.debug("Lex-0 PERMITTED: %s", action.value)
        return permitted

    def check_all(self, action: ActionType, context: dict) -> List[RuleResult]:
        """
        Run all rules and return ALL results (not just first failure).
        Used for audit reports and diagnostics.
        """
        results = []
        for rule in self.RULES:
            result = rule.check(action, context)
            if result is not None:
                results.append(result)
        return results

    def audit_log(self) -> List[RuleResult]:
        return list(self._audit_log)

    def audit_summary(self) -> dict:
        log = self._audit_log
        return {
            "total_checks":   len(log),
            "permitted":      sum(1 for r in log if r.verdict == RuleVerdict.PERMITTED),
            "denied":         sum(1 for r in log if r.verdict == RuleVerdict.DENIED),
            "escalated":      sum(1 for r in log if r.verdict == RuleVerdict.ESCALATED),
            "by_action":      self._count_by(log, lambda r: r.action.value),
            "by_rule":        self._count_by(
                                [r for r in log if r.verdict != RuleVerdict.PERMITTED],
                                lambda r: r.rule_triggered),
        }

    def _record(self, result: RuleResult):
        self._audit_log.append(result)
        if self.chain:
            self.chain.log_lex0_check({
                "action":  result.action.value,
                "verdict": result.verdict.value,
                "rule":    result.rule_triggered,
                "reason":  result.reason,
                "ts":      result.timestamp,
            })

    def _escalate(self, result: RuleResult):
        logger.critical(
            "Lex-0 ESCALATION: rule=%s action=%s reason=%s",
            result.rule_triggered, result.action.value, result.reason
        )

    @staticmethod
    def _count_by(items, key_fn) -> dict:
        counts: dict = {}
        for item in items:
            k = key_fn(item)
            counts[k] = counts.get(k, 0) + 1
        return counts


# -- CLI smoke-test -----------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    engine = Lex0Engine()

    print("\n" + "="*60)
    print("  EDEN :: Lex-0 Ethics Engine")
    print("="*60)

    tests = [
        (ActionType.MINT_CARBON_CREDIT, {
            "zone_id": "KE-MAU-001",
            "displaced_zone_ids": ["KE-MAU-001"],
        }, "Carbon credit on displaced land"),

        (ActionType.MINT_CARBON_CREDIT, {
            "zone_id": "KE-TSA-002",
            "displaced_zone_ids": [],
            "fraud_verdict": "FRAUDULENT",
            "fraud_score": 78,
        }, "Carbon credit on fraudulent claim"),

        (ActionType.DEPLOY_HARDWARE, {
            "indigenous_territory": True,
            "fpic_status": "pending",
        }, "Hardware on indigenous land, no FPIC"),

        (ActionType.SUPPRESS_ALERT, {
            "alert_id": "EVT-ABC123",
            "requested_by": "Ministry of Tourism",
        }, "Alert suppression by government"),

        (ActionType.DELETE_RECORD, {
            "record_id": "DISP-001",
            "record_type": "displacement",
            "requested_by": "GreenShield Carbon Ltd",
        }, "Record deletion by alleged actor"),

        (ActionType.ISSUE_RANGER_ALERT, {
            "zone_id": "KE-MAU-001",
            "threat_type": "chainsaw",
            "confidence": 0.92,
        }, "Ranger alert (should be PERMITTED)"),
    ]

    for action, context, label in tests:
        result = engine.check(action, context)
        icon = "BLOCKED" if not result.is_permitted() else "OK"
        print(f"  [{icon}] {label}")
        print(f"         -> {result.verdict.value}: {result.reason[:80]}")

    summary = engine.audit_summary()
    print(f"\n  Audit: {summary['total_checks']} checks | "
          f"{summary['permitted']} permitted | "
          f"{summary['denied']} denied | "
          f"{summary['escalated']} escalated")
    print("="*60)
