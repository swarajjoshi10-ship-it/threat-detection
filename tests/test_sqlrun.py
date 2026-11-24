import pytest

from threatdet.sqlrun import render, sql_literal_path


def test_render_substitutes():
    assert render("SELECT {{a}} + {{ b }}", {"a": 1, "b": 2}) == "SELECT 1 + 2"


def test_render_rejects_missing_and_unused():
    with pytest.raises(KeyError, match="missing"):
        render("SELECT {{a}}", {})
    with pytest.raises(KeyError, match="unused"):
        render("SELECT {{a}}", {"a": 1, "typo": 2})


def test_path_quotes_are_escaped(tmp_path):
    assert "''" in sql_literal_path(tmp_path / "o'brien.gz")
