#!/usr/bin/env python3
"""Offline tests for usage_check.py. Names and numbers here are made up.

Each test names, in its docstring, the change that turns it red.
"""
import ast
import contextlib
import datetime as dt
import http.server
import io
import os
import re
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usage_check as uc  # noqa: E402

ENV = {
    "USAGE_CHECK_TOKEN": "fake-token",
    "USAGE_CHECK_TARGET": "100",
    "USAGE_CHECK_LIMITS": "130,200",
    "GITHUB_REPOSITORY_OWNER": "someone",
}
TUESDAY_15 = dt.datetime(2030, 1, 15, 6, 17, tzinfo=dt.timezone.utc)  # line(14) = 45.2, line(13) = 41.9
MONDAY_14 = dt.datetime(2030, 1, 14, 6, 17, tzinfo=dt.timezone.utc)
DAY_1 = dt.datetime(2030, 1, 1, 6, 17, tzinfo=dt.timezone.utc)
FAR_EXPIRY = "2031-01-01 00:00:00 UTC"


def row(qty, repo="repo-a", day="2030-01-14", sku="Actions Linux", unit="Minutes", net=0.0, product="actions"):
    return {
        "date": day + "T00:00:00Z",
        "product": product,
        "sku": sku,
        "quantity": qty,
        "unitType": unit,
        "netAmount": net,
        "repositoryName": repo,
    }


class Fake:
    """Stands in for uc.fetch_json: answers by path, and records calls."""

    def __init__(self, items, public=("pub-a",), expiry=FAR_EXPIRY, usage_status=200, repos_status=200, usage_body=None, last_month=None,
                 last_month_status=200, last_month_url="year=2029&month=12"):
        self.items, self.public = items, list(public)
        self.expiry, self.usage_status, self.repos_status = expiry, usage_status, repos_status
        self.usage_body = usage_body
        self.last_month = last_month or []
        self.last_month_status = last_month_status
        self.last_month_url = last_month_url
        self.calls = []

    def __call__(self, url, token):
        self.calls.append(url)
        if "billing/usage" in url:
            headers = {} if self.expiry is None else {uc.EXPIRY_HEADER: self.expiry}
            body = self.usage_body if self.usage_body is not None else {"usageItems": self.items}
            if self.last_month_url and self.last_month_url in url:
                return self.last_month_status, headers, {"usageItems": self.last_month}
            return self.usage_status, headers, body
        page = int(re.search(r"page=(\d+)$", url).group(1))
        names = self.public[(page - 1) * uc.PAGE_SIZE : page * uc.PAGE_SIZE]
        return self.repos_status, {}, [{"name": n, "private": False} for n in names]


def run(items=(), now=TUESDAY_15, env=None, **kw):
    fake = Fake(list(items), **kw)
    code = uc.decide({**ENV, **(env or {})}, now, fake)
    return code, fake


class Counting(unittest.TestCase):
    def test_public_minutes_do_not_count(self):
        """Red if public repositories are counted as private."""
        code, _ = run([row(1000, repo="pub-a"), row(1)])
        self.assertEqual(code, uc.OK)

    def test_private_minutes_count(self):
        """Partner of the test above; red if nothing is ever counted."""
        code, _ = run([row(60)])
        self.assertEqual(code, uc.USAGE)

    def test_unknown_or_deleted_repository_counts(self):
        """Red if only names on a positive private list are counted."""
        code, _ = run([row(60, repo="deleted-long-ago")])
        self.assertEqual(code, uc.USAGE)

    def test_macos_counts_ten_times(self):
        """Red if the macOS multiplier is dropped."""
        code, _ = run([row(6, sku="Actions macOS 3-core")])
        self.assertEqual(code, uc.USAGE)
        code, _ = run([row(4, sku="Actions macOS 3-core")])
        self.assertEqual(code, uc.OK)

    def test_windows_counts_twice(self):
        """Red if the Windows multiplier is dropped."""
        code, _ = run([row(30, sku="Actions Windows")])
        self.assertEqual(code, uc.USAGE)

    def test_linux_counts_once(self):
        """Red if Linux gets a multiplier."""
        code, _ = run([row(40)])
        self.assertEqual(code, uc.OK)

    def test_storage_is_excluded(self):
        """Red if storage quantities are added to minutes."""
        code, _ = run([row(1000, sku="Actions storage", unit="GigabyteHours"), row(1)])
        self.assertEqual(code, uc.OK)

    def test_fractions_add_up(self):
        """Red if quantities are truncated to integers."""
        code, _ = run([row(0.6)] * 100)
        self.assertEqual(code, uc.USAGE)


class ReportShapes(unittest.TestCase):
    def test_the_documented_casing_and_qualified_names_also_count(self):
        """Red if only the live report's exact casing, or bare repository names, are understood."""
        self.assertEqual(run([row(60, product="Actions", unit="minutes")])[0], uc.USAGE)
        self.assertEqual(run([row(1000, repo="someone/pub-a", product="Actions", unit="minutes"), row(1)])[0], uc.OK)
        self.assertEqual(run([row(60, repo="someone/repo-a")])[0], uc.USAGE)
        self.assertEqual(run([row(1000, sku="Actions storage", unit="gigabyteHours"), row(1)])[0], uc.OK)

    def test_only_this_owners_exact_name_is_public(self):
        """Red if a name is judged public by its last segment, without the owner or the exact form."""
        for name in ("stranger/pub-a", "a/someone/pub-a", "/pub-a", "someone/pub-a/", "someone/pub-b"):
            with self.subTest(name=name):
                self.assertEqual(run([row(1000, repo=name), row(1)])[0], uc.USAGE)


class Unreadable(unittest.TestCase):
    def assertUnreadable(self, **kw):
        self.assertEqual(run(**kw)[0], uc.UNREADABLE)

    def test_no_actions_rows_at_all(self):
        """Red if an empty report reads as use of 0."""
        self.assertUnreadable(items=[])

    def test_no_actions_rows_because_product_renamed(self):
        """Red if a renamed product reads as use of 0."""
        self.assertUnreadable(items=[row(9999, product="Actions2")])

    def test_empty_report_is_fine_early_on_day_1(self):
        """Red if the first morning of a month goes to UNREADABLE instead of the heartbeat."""
        self.assertEqual(run([], now=DAY_1)[0], uc.HEARTBEAT)

    def test_empty_report_later_on_day_1_is_not(self):
        """Red if the day-1 allowance lasts all day."""
        self.assertEqual(run([], now=DAY_1.replace(hour=13))[0], uc.UNREADABLE)

    def test_renamed_unit(self):
        """Red if a renamed unit is skipped silently."""
        self.assertUnreadable(items=[row(9999, unit="seconds")])

    def test_unknown_sku_family(self):
        """Red if a new runner family is counted as Linux."""
        self.assertUnreadable(items=[row(1, sku="Actions Plan9")])

    def test_missing_repository_name(self):
        """Red if a row with no repository is skipped."""
        r = row(1)
        del r["repositoryName"]
        self.assertUnreadable(items=[r])

    def test_wrong_types(self):
        """Red if a bad quantity or date is not refused."""
        self.assertUnreadable(items=[row("many")])
        self.assertUnreadable(items=[row(True)])
        self.assertUnreadable(items=[row(float("nan"))])
        self.assertUnreadable(items=[row(-1)])
        self.assertUnreadable(items=[row(1, day="soon")])
        self.assertUnreadable(usage_body=[])
        self.assertUnreadable(usage_body={"usageItems": "x"})

    def test_server_error(self):
        """Red if a 500 reads as no data."""
        self.assertUnreadable(usage_status=500)
        self.assertUnreadable(repos_status=500, items=[row(1)])

    def test_empty_public_list(self):
        """Red if an empty list makes every repository private without saying so."""
        self.assertUnreadable(public=[], items=[row(1)])

    def test_bad_config(self):
        """Red if bad thresholds are accepted."""
        for env in (
            {"USAGE_CHECK_TARGET": ""},
            {"USAGE_CHECK_TARGET": "abc"},
            {"USAGE_CHECK_TARGET": "-1"},
            {"USAGE_CHECK_LIMITS": "130"},
            {"USAGE_CHECK_LIMITS": "130,x"},
            {"USAGE_CHECK_LIMITS": "90,200"},
            {"USAGE_CHECK_LIMITS": "130,120"},
        ):
            self.assertUnreadable(items=[row(1)], env=env)


class Token(unittest.TestCase):
    def test_refused(self):
        """Red if a refused token reads as bad data."""
        self.assertEqual(run([row(1)], usage_status=401)[0], uc.TOKEN)
        self.assertEqual(run([row(1)], usage_status=403)[0], uc.TOKEN)

    def test_missing(self):
        """Red if a missing secret is not reported as the token."""
        self.assertEqual(run([row(1)], env={"USAGE_CHECK_TOKEN": ""})[0], uc.TOKEN)

    def test_expires_soon(self):
        """Red if the expiry warning is dropped or its limit moved."""
        self.assertEqual(run([row(1)], expiry="2030-01-28 00:00:00 UTC")[0], uc.TOKEN)
        self.assertEqual(run([row(1)], expiry="2030-01-30 00:00:00 UTC")[0], uc.OK)

    def test_expiry_header_with_an_offset(self):
        """Red if the offset form is refused, which would make every run red for the token's life, or ignored."""
        self.assertEqual(run([row(1)], expiry="2031-01-01 00:00:00 +0200")[0], uc.OK)
        self.assertEqual(run([row(1)], expiry="2030-01-29 06:20:00 +0530")[0], uc.TOKEN)  # read as UTC it would pass
        self.assertEqual(run([row(1)], expiry="2030-01-29 12:00:00 -0800")[0], uc.OK)  # 14 days 13 hours away

    def test_no_expiry_header_is_fine(self):
        """Red if a token with no expiry is treated as broken."""
        self.assertEqual(run([row(1)], expiry=None)[0], uc.OK)

    def test_bad_expiry_header(self):
        """Red if an unparsable expiry passes silently."""
        self.assertEqual(run([row(1)], expiry="whenever")[0], uc.UNREADABLE)


class Levels(unittest.TestCase):
    def test_under_the_line(self):
        """Red if the line moves below use."""
        self.assertEqual(run([row(45)])[0], uc.OK)

    def test_quota_counts_today_and_fires_daily(self):
        """Red if reaching the quota is judged on complete days only, or fires once."""
        self.assertEqual(run([row(200, day="2030-01-15")])[0], uc.USAGE)
        self.assertEqual(run([row(200, day="2030-01-02")])[0], uc.USAGE)
        self.assertEqual(run([row(199, day="2030-01-02")])[0], uc.OK)

    def test_money_charged_on_any_row(self):
        """Red if a charge outside the counted rows is missed."""
        self.assertEqual(run([row(1, net=0.01)])[0], uc.USAGE)
        self.assertEqual(run([row(1), row(1, sku="Actions storage", unit="GigabyteHours", net=0.01)])[0], uc.USAGE)

    def test_precedence(self):
        """Red if usage hides a broken token or an unreadable report."""
        self.assertEqual(run([row(300)], expiry="2030-01-16 00:00:00 UTC")[0], uc.TOKEN)
        self.assertEqual(run([row(300)], usage_status=500)[0], uc.UNREADABLE)

    def test_a_reading_of_zero_is_not_healthy(self):
        """Red if a token that cannot see private rows, or renamed rows, read as fine all month."""
        storage = row(1, sku="Actions storage", unit="GigabyteHours")
        self.assertEqual(run([row(50, repo="pub-a")])[0], uc.UNREADABLE)
        self.assertEqual(run([storage])[0], uc.UNREADABLE)
        self.assertEqual(run([storage, row(9999, product="actions-compute")])[0], uc.UNREADABLE)
        seventh = TUESDAY_15.replace(day=7)
        self.assertEqual(run([row(50, repo="pub-a", day="2030-01-06")], now=seventh)[0], uc.OK)


class Pinned(unittest.TestCase):
    """Inputs where a changed comparison gives a different answer. Target 100, limits 130,200, Tuesday the 15th."""

    def test_same_day_minutes_do_not_decide_crossings(self):
        """Red if the ceiling or the line is judged on the day still in progress."""
        self.assertEqual(run([row(100, day="2030-01-13"), row(40, day="2030-01-15")])[0], uc.OK)
        self.assertEqual(run([row(30, day="2030-01-13"), row(20, day="2030-01-15")])[0], uc.OK)

    def test_ceiling_edges(self):
        """Red if at-the-ceiling stops counting, or a crossing two days ago fires again."""
        self.assertEqual(run([row(100, day="2030-01-13"), row(30, day="2030-01-14")])[0], uc.USAGE)
        self.assertEqual(run([row(130, day="2030-01-13")])[0], uc.OK)

    def test_line_edges(self):
        """Red if at-the-line counts as over, or a crossing exactly from the line is lost."""
        target = {"USAGE_CHECK_TARGET": "62"}  # line(14) = 28, line(13) = 26
        self.assertEqual(run([row(28, day="2030-01-14")], env=target)[0], uc.OK)
        self.assertEqual(run([row(26, day="2030-01-13"), row(3, day="2030-01-14")], env=target)[0], uc.USAGE)

    def test_the_day_before_yesterday_is_read_against_its_own_line(self):
        """Red if yesterday's line is used for the day before."""
        self.assertEqual(run([row(43, day="2030-01-13"), row(7, day="2030-01-14")])[0], uc.OK)

    def test_zero_guard_starts_on_day_8(self):
        """Red if the guard starts later than the floor."""
        for d, want in ((7, uc.OK), (8, uc.UNREADABLE), (10, uc.UNREADABLE)):
            now = TUESDAY_15.replace(day=d)
            self.assertEqual(run([row(50, repo="pub-a", day=f"2030-01-{d - 1:02d}")], now=now)[0], want)

    def test_storage_alone_is_no_data_early_in_the_month(self):
        """Red if storage rows count as seeing minutes data."""
        storage = row(1, sku="Actions storage", unit="GigabyteHours", day="2030-01-02")
        self.assertEqual(run([storage], now=TUESDAY_15.replace(day=3))[0], uc.UNREADABLE)

    def test_odd_minutes_rows_beside_a_good_row_are_refused(self):
        """Red if minutes under an unfamiliar product or name vanish while the good row keeps it ok."""
        for odd in (
            row(300, sku="Compute - MACOS"),
            row(300, product="actions-hosted", sku="actions macos 3-core"),
            row(5000, product="hosted-runners", sku="Linux 2-core"),
            row(9999, product="Actions2"),
            row(1, product="something", sku="Actions thing", unit="Units"),
            row(1000, product="runners", sku="Linux 2-core", unit="minutes"),
        ):
            self.assertEqual(run([row(1), odd])[0], uc.UNREADABLE, odd)

    def test_other_products_are_ignored(self):
        """Red if a product with nothing to do with Actions makes the check unreadable."""
        self.assertEqual(run([row(1), row(9, product="git_lfs", sku="LFS storage", unit="GigabyteHours")])[0], uc.OK)

    def test_a_charge_after_last_months_final_run_is_read_on_the_1st(self):
        """Red if the previous month's charge is never read."""
        charge = row(1, day="2029-12-31", net=3.0)
        self.assertEqual(run([], now=DAY_1, last_month=[charge])[0], uc.USAGE)
        self.assertEqual(run([], now=DAY_1, last_month=[row(1, day="2029-12-31")])[0], uc.HEARTBEAT)

    def test_last_month_is_the_calendar_month_before(self):
        """Red if the previous month is computed wrongly, for example always December or minus 31 days."""
        march = dt.datetime(2030, 3, 1, 6, 17, tzinfo=dt.timezone.utc)
        rows = [row(1, day="2030-02-28", net=3.0)]
        self.assertEqual(run([], now=march, last_month=rows, last_month_url="year=2030&month=2")[0], uc.USAGE)

    def test_a_failed_read_of_last_month_is_not_a_clean_month(self):
        """Red if a failed read of the old month is swallowed."""
        self.assertEqual(run([], now=DAY_1, last_month_status=500)[0], uc.UNREADABLE)
        self.assertEqual(run([], now=DAY_1, last_month_status=401)[0], uc.TOKEN)
        self.assertEqual(run([], now=DAY_1, last_month=["x"])[0], uc.UNREADABLE)

    def test_a_charge_from_last_month_is_not_read_on_other_days(self):
        """Red if the old month is read daily, which would stay red through the whole month."""
        _, fake = run([row(1)], last_month=[row(1, day="2029-12-31", net=3.0)])
        self.assertEqual(sum("month=12" in c for c in fake.calls), 0)


class Crossing(unittest.TestCase):
    def test_line_fires_on_the_crossing_only(self):
        """Red if the line fires every day while over, or misses the day after a crossing."""
        self.assertEqual(run([row(60, day="2030-01-13")])[0], uc.OK)  # already over yesterday's run; Tuesday
        self.assertEqual(run([row(40, day="2030-01-13"), row(20, day="2030-01-14")])[0], uc.USAGE)

    def test_line_repeats_on_mondays(self):
        """Red if the weekly reminder is dropped."""
        self.assertEqual(run([row(60, day="2030-01-12")], now=MONDAY_14)[0], uc.USAGE)

    def test_ceiling_fires_on_the_crossing_and_mondays_only(self):
        """Red if the ceiling fires every day, or Mondays go quiet while over it."""
        self.assertEqual(run([row(150, day="2030-01-13")])[0], uc.OK)
        self.assertEqual(run([row(150, day="2030-01-14")])[0], uc.USAGE)
        self.assertEqual(run([row(150, day="2030-01-12")], now=MONDAY_14)[0], uc.USAGE)

    def test_a_burst_after_the_run_is_not_missed(self):
        """Red if a crossing that happens after a day's run counts as already seen by that run."""
        sixteenth = TUESDAY_15.replace(day=16)
        self.assertEqual(run([row(150, day="2030-01-15")], now=sixteenth)[0], uc.USAGE)
        twenty_ninth = TUESDAY_15.replace(day=29)
        self.assertEqual(run([row(150, day="2030-01-28")], now=twenty_ninth)[0], uc.USAGE)

    def test_early_month_floor(self):
        """Red if the day-7 floor is removed: early use stays quiet under 7 days' worth."""
        third = TUESDAY_15.replace(day=3)
        self.assertEqual(run([row(20, day="2030-01-02")], now=third)[0], uc.OK)  # 100 * 7 / 31 = 22.6
        self.assertEqual(run([row(25, day="2030-01-02")], now=third)[0], uc.USAGE)

    def test_short_month(self):
        """Red if days in the month are fixed at 30 or 31."""
        now = dt.datetime(2030, 2, 28, 6, 17, tzinfo=dt.timezone.utc)
        crossed = [row(90, day="2030-02-26"), row(10, day="2030-02-27")]  # line(26) = 92.9, line(27) = 96.4
        self.assertEqual(run(crossed, now=now)[0], uc.USAGE)
        self.assertEqual(uc.line(100, 28, 28), 100)

    def test_a_month_of_steady_overuse_sends_few_emails(self):
        """Red if a month over the line sends a mail a day, or goes quiet. Each run sees rows through yesterday."""
        rows, reds = [], []
        for d in range(2, 32):
            now = TUESDAY_15.replace(day=d)
            rows.append(row(6, day=f"2030-01-{d - 1:02d}"))
            if run(list(rows), now=now)[0] == uc.USAGE:
                reds.append(d)
        self.assertEqual(reds, [5, 7, 14, 21, 23, 28])  # pace crossing, Mondays, ceiling crossing


class Heartbeat(unittest.TestCase):
    def test_first_of_the_month_goes_red_once(self):
        """Red if the heartbeat is dropped, which would make a dead check look quiet."""
        self.assertEqual(run([row(1, day="2030-01-01")], now=DAY_1)[0], uc.HEARTBEAT)
        self.assertEqual(run([row(1, day="2030-01-02")], now=DAY_1.replace(day=2))[0], uc.OK)

    def test_force_only_after_a_good_read(self):
        """Red if a forced run skips the read, so a test could pass with a dead token."""
        env = {"USAGE_CHECK_FORCE": "1"}
        self.assertEqual(run([row(1)], env=env)[0], uc.HEARTBEAT)
        self.assertEqual(run([row(1)], env=env, usage_status=401)[0], uc.TOKEN)
        self.assertEqual(run([row(1)], env=env, usage_status=500)[0], uc.UNREADABLE)

    def test_a_real_problem_wins_over_force(self):
        """Red if forcing hides a real level."""
        self.assertEqual(run([row(300)], env={"USAGE_CHECK_FORCE": "1"})[0], uc.USAGE)


class Fetching(unittest.TestCase):
    def test_public_list_reads_all_pages(self):
        """Red if pagination stops at the first page."""
        names = [f"pub-{i}" for i in range(uc.PAGE_SIZE + 5)]
        code, fake = run([row(1000, repo=names[-1]), row(1)], public=names)
        self.assertEqual(code, uc.OK)
        self.assertEqual(sum("/repos?" in c for c in fake.calls), 2)

    def test_usage_asks_for_this_month(self):
        """Red if the month in the query is wrong."""
        _, fake = run([row(1)])
        self.assertIn("year=2030&month=1", fake.calls[0])
        self.assertIn("/users/someone/settings/billing/usage", fake.calls[0])

    def test_private_entry_in_the_public_list_is_not_public(self):
        """Red if the private flag is ignored."""
        fake = Fake([row(60, repo="repo-a")], public=["pub-a"])
        original = fake.__call__

        def with_private(url, token):
            status, headers, body = original(url, token)
            if "/repos?" in url:
                body = body + [{"name": "repo-a", "private": True}]
            return status, headers, body

        self.assertEqual(uc.decide(ENV, TUESDAY_15, with_private), uc.USAGE)


class Output(unittest.TestCase):
    SENTINEL = "sentinel-private-name-98765"

    def line(self, fetch, env=ENV):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = uc.main(env, TUESDAY_15, fetch)
        return status, out.getvalue() + err.getvalue()

    def test_ok(self):
        """Red if a good run prints more than one word."""
        status, text = self.line(Fake([row(1)]))
        self.assertEqual((status, text), (0, "ok\n"))

    def test_attention_has_no_figure(self):
        """Red if a red run prints anything but its one line."""
        status, text = self.line(Fake([row(60, repo=self.SENTINEL)]))
        self.assertEqual((status, text), (1, f"attention {uc.USAGE}\n"))

    def test_every_failure_is_one_line(self):
        """Red if input text can reach the log on any failure path."""
        s = self.SENTINEL
        bad_bodies = [
            {"usageItems": [{"quantity": s, "repositoryName": s}]},
            {"usageItems": [row(s, repo=s, sku=s, unit=s)]},
            {"usageItems": [row(98765, repo={"a": s})]},
            [s],
            s,
            None,
        ]
        for body in bad_bodies:
            fake = Fake([], usage_body=body if body is not None else {"x": s})
            status, text = self.line(fake)
            self.assertEqual((status, text), (1, f"attention {uc.UNREADABLE}\n"), body)
        for env in ({**ENV, "USAGE_CHECK_TARGET": s}, {**ENV, "USAGE_CHECK_LIMITS": s + ",98765"}):
            status, text = self.line(Fake([row(1)]), env)
            self.assertEqual((status, text), (1, f"attention {uc.UNREADABLE}\n"))

    def test_an_exception_in_fetching_is_one_line(self):
        """Red if an exception's text reaches the log."""

        def boom(url, token):
            raise RuntimeError(self.SENTINEL)

        status, text = self.line(boom)
        self.assertEqual((status, text), (1, f"attention {uc.UNREADABLE}\n"))

    def test_the_real_entry_point_silences_stderr(self):
        """Red if the program's entry stops pointing stderr at /dev/null before anything runs."""
        here = os.path.dirname(os.path.abspath(__file__))
        code = (
            "import sys, os, usage_check as uc\n"
            f"def boom(*a, **k):\n    sys.stderr.write({self.SENTINEL!r}); os.write(2, b{self.SENTINEL!r}); raise ValueError({self.SENTINEL!r})\n"
            "uc.fetch_json = boom\n"
            "uc.entry()\n"
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith("USAGE_CHECK")}
        env.update(ENV)
        env["PYTHONPATH"] = here
        p = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual((p.returncode, p.stdout + p.stderr), (1, f"attention {uc.UNREADABLE}\n"))

    def test_no_large_number_in_the_program(self):
        """Red if a threshold is written into the public script instead of a secret."""
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage_check.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        numbers = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (int, float))]
        self.assertGreater(len(numbers), 0)
        self.assertLess(max(numbers), 1000)


class FetchJson(unittest.TestCase):
    """The real fetch function against a local server."""

    def setUp(self):
        hits = self.hits = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                hits[self.path] = hits.get(self.path, 0) + 1
                if self.path == "/moved":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.end_headers()
                    return
                status = {"/refused": 401, "/broken": 500}.get(self.path, 200)
                self.send_response(status)
                self.send_header(uc.EXPIRY_HEADER, FAR_EXPIRY)
                self.end_headers()
                self.wfile.write(b'{"a": 1}')

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        wait, uc.RETRY_WAIT_SECONDS = uc.RETRY_WAIT_SECONDS, 0
        self.addCleanup(setattr, uc, "RETRY_WAIT_SECONDS", wait)

    def test_good_reply(self):
        """Red if the headers or body stop reaching the caller."""
        status, headers, body = uc.fetch_json(self.base + "/ok", "fake")
        self.assertEqual((status, headers[uc.EXPIRY_HEADER], body), (200, FAR_EXPIRY, {"a": 1}))

    def test_refused_is_not_retried(self):
        """Red if a refused token is retried."""
        self.assertEqual(uc.fetch_json(self.base + "/refused", "fake")[0], 401)
        self.assertEqual(self.hits["/refused"], 1)

    def test_server_error_is_retried_once(self):
        """Red if a passing server error goes straight to a red run, or retries forever."""
        self.assertEqual(uc.fetch_json(self.base + "/broken", "fake")[0], 500)
        self.assertEqual(self.hits["/broken"], 2)

    def test_redirect_is_not_followed(self):
        """Red if the token can travel to wherever a redirect points."""
        self.assertEqual(uc.fetch_json(self.base + "/moved", "fake")[0], 302)
        self.assertNotIn("/elsewhere", self.hits)


class Deadline(unittest.TestCase):
    def test_a_stall_ends_as_one_red_line_before_the_job_limit(self):
        """Red if a stall can run on to the job's limit, which ends cancelled and may send no email."""
        here = os.path.dirname(os.path.abspath(__file__))
        code = (
            "import time, usage_check as uc\n"
            "uc.DEADLINE_SECONDS = 1\n"
            "def stall(*a, **k):\n    time.sleep(30)\n"
            "uc.fetch_json = stall\n"
            "uc.entry()\n"
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith("USAGE_CHECK")}
        env.update(ENV)
        env["PYTHONPATH"] = here
        p = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual((p.returncode, p.stdout + p.stderr), (1, f"attention {uc.UNREADABLE}\n"))

    def test_the_deadline_is_inside_the_job_limit(self):
        """Red if the workflow's limit is cut below the program's deadline plus a margin."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows", "usage-check.yml")
        with open(path, encoding="utf-8") as f:
            limit = int(re.search(r"timeout-minutes:\s*(\d+)", f.read()).group(1))
        self.assertGreaterEqual(limit * 60, uc.DEADLINE_SECONDS + 30)


class Workflow(unittest.TestCase):
    def test_shape(self):
        """Red if the workflow gains a trigger, a permission, or a figure."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows", "usage-check.yml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("permissions: {}", text)
        triggers = text.split("on:\n", 1)[1].split("\npermissions", 1)[0]
        self.assertIn("schedule:", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        for bad in ("pull_request", "push:", "workflow_run", "issue"):
            self.assertNotIn(bad, triggers)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("persist-credentials: false", text)
        self.assertNotRegex(text, r"\b\d{4,}\b")  # no threshold; the pinned action id has letters
        for use in re.findall(r"uses:\s*(\S+)", text):
            self.assertRegex(use, r"@[0-9a-f]{40}$")
        self.assertEqual(text.count("secrets.USAGE_CHECK_TOKEN"), 1)


if __name__ == "__main__":
    unittest.main()
