#!/usr/bin/env python3
"""Offline tests for usage_check.py. Names and numbers here are made up.

Each test names, in its docstring, the change that turns it red.
"""
import contextlib
import datetime as dt
import io
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usage_check as uc  # noqa: E402

ENV = {
    "USAGE_CHECK_TOKEN": "fake-token",
    "USAGE_CHECK_TARGET": "100",
    "USAGE_CHECK_LIMITS": "130,200",
    "GITHUB_REPOSITORY_OWNER": "someone",
}
TUESDAY_15 = dt.datetime(2030, 1, 15, 6, 17, tzinfo=dt.timezone.utc)  # target line: 100 * 15 / 31 = 48.4
MONDAY_14 = dt.datetime(2030, 1, 14, 6, 17, tzinfo=dt.timezone.utc)
DAY_1 = dt.datetime(2030, 1, 1, 6, 17, tzinfo=dt.timezone.utc)
FAR_EXPIRY = "2031-01-01 00:00:00 UTC"


def row(qty, repo="repo-a", day="2030-01-15", sku="Actions Linux", unit="Minutes", net=0.0, product="actions"):
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

    def __init__(self, items, public=("pub-a",), expiry=FAR_EXPIRY, usage_status=200, repos_status=200, usage_body=None):
        self.items, self.public = items, list(public)
        self.expiry, self.usage_status, self.repos_status = expiry, usage_status, repos_status
        self.usage_body = usage_body
        self.calls = []

    def __call__(self, url, token):
        self.calls.append(url)
        if "billing/usage" in url:
            headers = {} if self.expiry is None else {uc.EXPIRY_HEADER: self.expiry}
            body = self.usage_body if self.usage_body is not None else {"usageItems": self.items}
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
        code, _ = run([row(1000, repo="pub-a")])
        self.assertEqual(code, uc.OK)

    def test_private_minutes_count(self):
        """Partner of the test above; red if nothing is ever counted."""
        code, _ = run([row(60)])
        self.assertEqual(code, uc.LINE)

    def test_unknown_or_deleted_repository_counts(self):
        """Red if only names on a positive private list are counted."""
        code, _ = run([row(60, repo="deleted-long-ago")])
        self.assertEqual(code, uc.LINE)

    def test_macos_counts_ten_times(self):
        """Red if the macOS multiplier is dropped."""
        code, _ = run([row(6, sku="Actions macOS 3-core")])
        self.assertEqual(code, uc.LINE)
        code, _ = run([row(4, sku="Actions macOS 3-core")])
        self.assertEqual(code, uc.OK)

    def test_windows_counts_twice(self):
        """Red if the Windows multiplier is dropped."""
        code, _ = run([row(30, sku="Actions Windows")])
        self.assertEqual(code, uc.LINE)

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
        self.assertEqual(code, uc.LINE)


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
        self.assertUnreadable(items=[row(9999, unit="minutes")])

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

    def test_no_expiry_header_is_fine(self):
        """Red if a token with no expiry is treated as broken."""
        self.assertEqual(run([row(1)], expiry=None)[0], uc.OK)

    def test_bad_expiry_header(self):
        """Red if an unparsable expiry passes silently."""
        self.assertEqual(run([row(1)], expiry="whenever")[0], uc.UNREADABLE)


class Levels(unittest.TestCase):
    def test_under_the_line(self):
        """Red if the line moves below use."""
        self.assertEqual(run([row(48)])[0], uc.OK)

    def test_quota(self):
        """Red if reaching the quota is not reported; fires every day."""
        items = [row(200, day="2030-01-02")]
        self.assertEqual(run(items)[0], uc.QUOTA)
        self.assertEqual(run([row(199, day="2030-01-02")])[0], uc.OK)

    def test_money_charged_on_any_row(self):
        """Red if a charge outside the counted rows is missed."""
        self.assertEqual(run([row(1, net=0.01)])[0], uc.CHARGED)
        self.assertEqual(run([row(1), row(1, sku="Actions storage", unit="GigabyteHours", net=0.01)])[0], uc.CHARGED)

    def test_precedence(self):
        """Red if a lower level hides a higher one."""
        self.assertEqual(run([row(300, net=1)])[0], uc.QUOTA)
        self.assertEqual(run([row(150, net=1, day="2030-01-15")])[0], uc.CHARGED)
        self.assertEqual(run([row(150, day="2030-01-15")])[0], uc.CEILING)
        self.assertEqual(run([row(300)], expiry="2030-01-16 00:00:00 UTC")[0], uc.TOKEN)
        self.assertEqual(run([row(300)], usage_status=500)[0], uc.UNREADABLE)


class Crossing(unittest.TestCase):
    def test_line_fires_on_the_crossing_only(self):
        """Red if the pace line fires every day while over."""
        over_yesterday = [row(60, day="2030-01-14")]
        self.assertEqual(run(over_yesterday)[0], uc.OK)  # 60 > line(14) = 45.2 already; Tuesday: quiet
        crossed_today = [row(40, day="2030-01-14"), row(20, day="2030-01-15")]
        self.assertEqual(run(crossed_today)[0], uc.LINE)

    def test_line_repeats_on_mondays(self):
        """Red if the weekly reminder is dropped."""
        self.assertEqual(run([row(60, day="2030-01-12")], now=MONDAY_14)[0], uc.LINE)

    def test_ceiling_fires_on_the_crossing_and_mondays_only(self):
        """Red if the ceiling fires every day, or never repeats."""
        self.assertEqual(run([row(150, day="2030-01-14")])[0], uc.OK)
        self.assertEqual(run([row(150, day="2030-01-12")], now=MONDAY_14)[0], uc.CEILING)
        self.assertEqual(run([row(100, day="2030-01-14"), row(50, day="2030-01-15")])[0], uc.CEILING)

    def test_early_month_floor(self):
        """Red if the day-7 floor is removed: a burst on day 3 stays quiet under 7 days' worth."""
        third = dt.datetime(2030, 1, 3, 6, 17, tzinfo=dt.timezone.utc)
        self.assertEqual(run([row(20, day="2030-01-03")], now=third)[0], uc.OK)  # 100 * 7 / 31 = 22.6
        self.assertEqual(run([row(25, day="2030-01-03")], now=third)[0], uc.LINE)

    def test_short_month(self):
        """Red if days in the month are fixed at 30 or 31."""
        now = dt.datetime(2030, 2, 28, 6, 17, tzinfo=dt.timezone.utc)
        crossed = [row(95, day="2030-02-27"), row(10, day="2030-02-28")]  # line(27) = 96.4, line(28) = 100
        self.assertEqual(run(crossed, now=now)[0], uc.LINE)
        self.assertEqual(uc.line(100, 28, 28), 100)

    def test_a_month_sends_few_emails(self):
        """Red if a month over the line sends a mail a day. Steady use, over from day 7 on."""
        reds = 0
        rows = []
        for d in range(1, 32):
            now = dt.datetime(2030, 1, d, 6, 17, tzinfo=dt.timezone.utc)
            rows.append(row(6, day=f"2030-01-{d:02d}"))
            code = run(list(rows), now=now)[0]
            if code in (uc.LINE, uc.CEILING):
                reds += 1
        self.assertGreater(reds, 0)
        self.assertLessEqual(reds, 8)


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
        self.assertEqual(run([row(300)], env={"USAGE_CHECK_FORCE": "1"})[0], uc.QUOTA)


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

        self.assertEqual(uc.decide(ENV, TUESDAY_15, with_private), uc.LINE)


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
        self.assertEqual((status, text), (1, f"attention {uc.LINE}\n"))

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

    def test_no_figure_in_the_program(self):
        """Red if a threshold is written into the public script."""
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage_check.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotRegex(text, r"\b(1500|1800|3000|2884)\b")


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
        self.assertNotRegex(text, r"\b(1500|1800|3000)\b")
        for use in re.findall(r"uses:\s*(\S+)", text):
            self.assertRegex(use, r"@[0-9a-f]{40}$")
        self.assertEqual(text.count("secrets.USAGE_CHECK_TOKEN"), 1)


if __name__ == "__main__":
    unittest.main()
