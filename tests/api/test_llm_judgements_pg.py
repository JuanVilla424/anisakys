"""LLM judge audit, daily budget and earlier verdicts on real PostgreSQL (llm_judgements)."""

import json
from typing import Any, Iterator, List

import pytest
import requests
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from src.detection.llm_judge import PROMPT_VERSION, JudgeConfig, LLMJudge

VERDICT = {"is_phishing": False, "brand": None, "confidence": 0.8, "signals": [], "reasons": "x"}


class FakeSession:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def post(self, url: str, **_kwargs: Any) -> requests.Response:
        self.calls.append(url)
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(
            {
                "choices": [{"message": {"content": json.dumps(VERDICT)}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 100},
            }
        ).encode()
        return response


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_engine(migrated_db_url)
    with eng.begin() as conn:
        conn.execute(text("TRUNCATE llm_judgements RESTART IDENTITY"))
    yield eng
    eng.dispose()


def _judge(engine: Engine, session: FakeSession, budget: float = 1.0) -> LLMJudge:
    config = JudgeConfig(
        provider="openai_compatible",
        model="deepseek-flash",
        base_url="https://api.deepseek.com",
        api_key="sk-test-not-a-real-key",
        daily_budget_usd=budget,
    )
    return LLMJudge(config, engine=engine, session=session)  # type: ignore[arg-type]


def test_every_call_is_audited_without_the_key(engine):
    session = FakeSession()

    judgement = _judge(engine, session).judge("https://bank-demo.com/", page_text="hello")

    with engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM llm_judgements")).mappings().one()
    assert row["status"] == "ok" and row["verdict"] == VERDICT
    assert row["provider"] == "openai_compatible" and row["model"] == "deepseek-flash"
    assert row["prompt_version"] == PROMPT_VERSION
    assert row["input_sha256"] == judgement.input_sha256
    assert (row["input_tokens"], row["output_tokens"]) == (1000, 100)
    assert float(row["cost_usd"]) == judgement.cost_usd > 0
    assert "sk-test" not in json.dumps({k: str(v) for k, v in row.items()})


def test_an_earlier_verdict_is_reused_by_another_process(engine):
    first, second = FakeSession(), FakeSession()
    _judge(engine, first).judge("https://bank-demo.com/", page_text="hello")

    again = _judge(engine, second).judge("https://bank-demo.com/", page_text="hello")

    assert again.cached and again.verdict == VERDICT
    assert first.calls and not second.calls


def test_the_budget_counts_every_process_spending_today(engine):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO llm_judgements (url, input_sha256, provider, model, prompt_version, "
                "status, cost_usd) VALUES ('https://x/', 'h', 'p', 'm', 'v', 'ok', 0.5)"
            )
        )
    session = FakeSession()

    judgement = _judge(engine, session, budget=0.5).judge("https://bank-demo.com/")

    assert judgement.status == "budget" and not session.calls
    with engine.connect() as conn:
        statuses = conn.execute(text("SELECT status FROM llm_judgements ORDER BY id")).scalars()
        assert list(statuses) == ["ok", "budget"]


def test_spending_of_earlier_days_does_not_count(engine):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO llm_judgements (url, input_sha256, provider, model, prompt_version, "
                "status, cost_usd, created_at) VALUES ('https://x/', 'h', 'p', 'm', 'v', 'ok', "
                "5, now() - interval '2 days')"
            )
        )
    session = FakeSession()

    assert _judge(engine, session).judge("https://bank-demo.com/").status == "ok"
