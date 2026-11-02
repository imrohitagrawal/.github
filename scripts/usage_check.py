#!/usr/bin/env python3
"""Daily check of this account's Actions usage. Prints one line and nothing else.

Runs in a public repository, so its log is public: it prints `ok`, or `attention <n>` and exits 1.
It never prints input text; figures and thresholds come only from secrets. What each number means,
and what to do about it, is in the owner's private notes.
"""
import calendar
import datetime as dt
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request

OK, UNREADABLE, TOKEN, QUOTA, CHARGED, CEILING, LINE, HEARTBEAT = 0, 1, 2, 3, 4, 5, 6, 7

API = "https://api.github.com"
API_VERSION = "2022-11-28"
EXPIRY_HEADER = "github-authentication-token-expiration"
PAGE_SIZE = 100
MAX_PAGES = 20
TIMEOUT_SECONDS = 30
RETRY_WAIT_SECONDS = 30
TOKEN_WARNING_DAYS = 14
# The line does not start below this many days' worth: a month's dependency updates land in its first days.
FLOOR_DAYS = 7
# Day 1's report may not exist yet in the morning.
DAY_1_GRACE_HOUR = 12
# GitHub's published multipliers for included minutes.
SKU_FACTORS = (("macOS", 10), ("Windows", 2), ("Linux", 1))
MONDAY = 0


class Unreadable(Exception):
    pass


class TokenProblem(Exception):
    pass


def fetch_json(url, token):
    """Returns (status, headers, parsed body). One retry on a network failure or a server error."""
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VERSION,
    })
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as reply:
                return reply.status, {k.lower(): v for k, v in reply.headers.items()}, json.load(reply)
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == 2:
                return error.code, {}, None
        except (OSError, ValueError):
            if attempt == 2:
                raise
        time.sleep(RETRY_WAIT_SECONDS)
    raise Unreadable


def positive_int(text):
    if not (isinstance(text, str) and text.isascii() and text.isdigit() and int(text) > 0):
        raise Unreadable
    return int(text)


def read_config(env):
    target = positive_int(env.get("USAGE_CHECK_TARGET", ""))
    limits = env.get("USAGE_CHECK_LIMITS", "").split(",")
    if len(limits) != 2:
        raise Unreadable
    ceiling, quota = positive_int(limits[0]), positive_int(limits[1])
    if not target < ceiling < quota:
        raise Unreadable
    return target, ceiling, quota


def line(target, day, days_in_month):
    return target * max(day, FLOOR_DAYS) / days_in_month


def check_status(status):
    if status in (401, 403):
        raise TokenProblem
    if status != 200:
        raise Unreadable


def check_expiry(headers, now):
    value = headers.get(EXPIRY_HEADER)
    if value is None:
        return
    try:
        expires = dt.datetime.strptime(value.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except (ValueError, AttributeError):
        raise Unreadable from None
    if expires - now < dt.timedelta(days=TOKEN_WARNING_DAYS):
        raise TokenProblem


def read_public_names(owner, token, fetch):
    names = set()
    for page in range(1, MAX_PAGES + 1):
        status, _, body = fetch(f"{API}/users/{owner}/repos?type=owner&per_page={PAGE_SIZE}&page={page}", token)
        check_status(status)
        if not isinstance(body, list):
            raise Unreadable
        for repo in body:
            if not (isinstance(repo, dict) and isinstance(repo.get("name"), str)):
                raise Unreadable
            if repo.get("private") is False:
                names.add(repo["name"])
        if len(body) < PAGE_SIZE:
            if not names:
                raise Unreadable
            return names
    raise Unreadable


def factor_for(sku):
    if isinstance(sku, str) and sku.startswith("Actions "):
        for word, factor in SKU_FACTORS:
            if word in sku:
                return factor
    raise Unreadable


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise Unreadable
    return value


def read_rows(body, public, now):
    """Returns (minutes used before today, minutes used in all, money charged, any Actions row seen)."""
    if not isinstance(body, dict) or not isinstance(body.get("usageItems"), list):
        raise Unreadable
    before_today = total = 0.0
    charged = seen = False
    for row in body["usageItems"]:
        if not isinstance(row, dict):
            raise Unreadable
        if number(row.get("netAmount")) > 0:
            charged = True
        if row.get("product") != "actions":
            continue
        seen = True
        if row.get("unitType") == "GigabyteHours":
            continue
        if row.get("unitType") != "Minutes" or not isinstance(row.get("repositoryName"), str):
            raise Unreadable
        minutes = number(row.get("quantity")) * factor_for(row.get("sku"))
        day = row.get("date")
        if not isinstance(day, str):
            raise Unreadable
        try:
            day = dt.date.fromisoformat(day[:10])
        except ValueError:
            raise Unreadable from None
        if row["repositoryName"] in public:
            continue
        total += minutes
        if day < now.date():
            before_today += minutes
    return before_today, total, charged, seen


def decide(env, now, fetch):
    """Returns one of the level numbers. Precedence is the order of the checks below."""
    try:
        target, ceiling, quota = read_config(env)
        token = env.get("USAGE_CHECK_TOKEN", "")
        owner = env.get("GITHUB_REPOSITORY_OWNER", "")
        if not token:
            return TOKEN
        if not owner:
            return UNREADABLE
        status, headers, body = fetch(
            f"{API}/users/{owner}/settings/billing/usage?year={now.year}&month={now.month}", token)
        check_status(status)
        check_expiry(headers, now)
        public = read_public_names(owner, token, fetch)
        before_today, total, charged, seen = read_rows(body, public, now)
    except TokenProblem:
        return TOKEN
    except Unreadable:
        return UNREADABLE
    if not seen and not (now.day == 1 and now.hour < DAY_1_GRACE_HOUR):
        return UNREADABLE

    if total >= quota:
        return QUOTA
    if charged:
        return CHARGED
    days = calendar.monthrange(now.year, now.month)[1]
    monday = now.weekday() == MONDAY
    if total >= ceiling and (monday or before_today < ceiling):
        return CEILING
    over_yesterday = now.day > 1 and before_today > line(target, now.day - 1, days)
    if total > line(target, now.day, days) and (monday or not over_yesterday):
        return LINE
    if now.day == 1 or env.get("USAGE_CHECK_FORCE"):
        return HEARTBEAT
    return OK


def main(env, now, fetch):
    try:
        code = decide(env, now, fetch)
    except Exception:  # Any other failure must also print nothing but the one line.
        code = UNREADABLE
    print("ok" if code == OK else f"attention {code}")
    return 0 if code == OK else 1


def entry():
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 2)
    sys.stderr = open(devnull, "w", encoding="utf-8")
    sys.exit(main(os.environ, dt.datetime.now(dt.timezone.utc), fetch_json))


if __name__ == "__main__":
    entry()
