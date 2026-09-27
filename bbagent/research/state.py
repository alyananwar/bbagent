"""Research state machine.

Explicit states with explicit legal transitions, so "the scanners finished" can
never be confused with "the engagement is done". A zero-finding scan is a
transition INTO application modeling, not an exit.

Only TERMINAL states end an engagement, and there are exactly three of them:
budget exhausted, no meaningful hypotheses left, or a hard authorization stop.
"""
from enum import Enum
from typing import Dict, FrozenSet


class ResearchState(str, Enum):
    SCOPE_VERIFIED = "scope_verified"
    RECON = "recon"
    APPLICATION_MODELING = "application_modeling"
    HYPOTHESIS_GENERATED = "hypothesis_generated"
    INVESTIGATION = "investigation"
    VALIDATION = "validation"
    BLOCKED_ON_RESEARCHER = "blocked_on_researcher"
    BUDGET_EXHAUSTED = "budget_exhausted"
    HYPOTHESES_EXHAUSTED = "hypotheses_exhausted"
    HALTED_UNAUTHORIZED = "halted_unauthorized"


TERMINAL: FrozenSet[ResearchState] = frozenset({
    ResearchState.BUDGET_EXHAUSTED,
    ResearchState.HYPOTHESES_EXHAUSTED,
    ResearchState.HALTED_UNAUTHORIZED,
})

# A blocker is NOT terminal: the loop parks there and resumes when the human
# supplies what was missing.
_ANY_STOP = frozenset({ResearchState.BLOCKED_ON_RESEARCHER}) | TERMINAL

TRANSITIONS: Dict[ResearchState, FrozenSet[ResearchState]] = {
    ResearchState.SCOPE_VERIFIED: frozenset({ResearchState.RECON}) | _ANY_STOP,
    # recon completing -- with hits or with NOTHING -- goes to modeling.
    ResearchState.RECON: frozenset({
        ResearchState.APPLICATION_MODELING}) | _ANY_STOP,
    ResearchState.APPLICATION_MODELING: frozenset({
        ResearchState.HYPOTHESIS_GENERATED}) | _ANY_STOP,
    ResearchState.HYPOTHESIS_GENERATED: frozenset({
        ResearchState.INVESTIGATION,
        ResearchState.APPLICATION_MODELING}) | _ANY_STOP,
    ResearchState.INVESTIGATION: frozenset({
        ResearchState.VALIDATION,
        ResearchState.APPLICATION_MODELING,   # learned something, remodel
        ResearchState.HYPOTHESIS_GENERATED,   # rejected, next hypothesis
        ResearchState.RECON}) | _ANY_STOP,    # need more surface
    ResearchState.VALIDATION: frozenset({
        ResearchState.HYPOTHESIS_GENERATED,
        ResearchState.INVESTIGATION,
        ResearchState.APPLICATION_MODELING}) | _ANY_STOP,
    # parked on a human; resumes into whatever needed the input
    ResearchState.BLOCKED_ON_RESEARCHER: frozenset({
        ResearchState.APPLICATION_MODELING,
        ResearchState.HYPOTHESIS_GENERATED,
        ResearchState.INVESTIGATION,
        ResearchState.VALIDATION,
        ResearchState.RECON}) | TERMINAL,
    ResearchState.BUDGET_EXHAUSTED: frozenset(),
    ResearchState.HYPOTHESES_EXHAUSTED: frozenset(),
    ResearchState.HALTED_UNAUTHORIZED: frozenset(),
}


class IllegalTransition(Exception):
    pass


def can(src: ResearchState, dst: ResearchState) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def advance(src: ResearchState, dst: ResearchState) -> ResearchState:
    """Return dst, or raise. Fails loudly: a wrong transition is a bug, and a
    silently-accepted one is how a pipeline quietly exits early."""
    if not can(src, dst):
        raise IllegalTransition("%s -> %s is not a legal research transition"
                                % (src.value, dst.value))
    return dst


def is_terminal(state: ResearchState) -> bool:
    return state in TERMINAL
