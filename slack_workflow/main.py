import os
import json
import hmac
import hashlib
import requests
from flask import Request, make_response
from urllib.parse import parse_qs
from base64 import b64encode,b64decode
import time
import threading
from flask import jsonify
import yaml
from github import Github
from pathlib import Path

def read_template(relative_path):
    base_dir = Path(__file__).parent
    full_path = base_dir / relative_path
    return full_path.read_text()



# --- ENV VARS ---
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_USER = os.getenv("GITHUB_USER")
GITHUB_REPOS = os.getenv("GITHUB_REPOS").split(",")
JIRA_PROJECT_KEY = "BAC"
JIRA_BASE_URL = "https://sukiai.atlassian.net"

HEADERS_GITHUB = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}
JIRA_HEADERS = {
    "Authorization": f"Basic {b64encode(f'{JIRA_EMAIL}:{JIRA_API_TOKEN}'.encode()).decode()}",
    "Accept": "application/json"
}

# --- Raw Command Permissions by Email ---
RAW_COMMAND_PERMISSIONS = {
    "/create-repo": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/create-release-branch": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/jira-report": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/jira-update": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/test-deploy": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/stage-deploy": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/prod-deploy": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/enforce-pr-title-check": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/reverse-merge": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ],
    "/enforce-branch-rules": [
    "averma@suki.ai",
    "pkumar@suki.ai",
    "ssingh@suki.ai"
    ],
    "/repo-settings": [
        "averma@suki.ai",
        "pkumar@suki.ai",
        "ssingh@suki.ai"
    ]

}

def get_slack_user_map():
    url = "https://slack.com/api/users.list"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    res = requests.get(url, headers=headers)
    print("🔍 Slack users response:", res.json()) 

    user_map = {}
    if res.status_code == 200 and res.json().get("ok"):
        for member in res.json()["members"]:
            profile = member.get("profile", {})
            email = profile.get("email")
            user_id = member.get("id")
            if email:
                user_map[email.lower()] = user_id

    user_map["averma@suki.ai"] = "U090UPJC1S8"

    return user_map

try:
    slack_user_map = get_slack_user_map()
    slack_user_map["averma@suki.ai"] = "U090UPJC1S8"
    
    print(f"✅ slack_user_map = {slack_user_map}") 
    COMMAND_PERMISSIONS = {}
    for cmd, emails in RAW_COMMAND_PERMISSIONS.items():
        resolved_ids = [slack_user_map.get(email.lower()) for email in emails if slack_user_map.get(email.lower())]
        COMMAND_PERMISSIONS[cmd] = resolved_ids
    print(f"✅ COMMAND_PERMISSIONS resolved: {COMMAND_PERMISSIONS}")
except Exception as e:
    print(f"⚠️ Failed to resolve command permissions: {e}")
    COMMAND_PERMISSIONS = {}

# --- ENTRY POINT ---
def slack_workflow(request: Request):
    if not is_valid_slack_request(request):
        return make_response("Invalid request", 400)
    
    path = request.path

    if path == "/slack/interact":
        payload = json.loads(request.form["payload"])
        if payload["type"] == "view_submission":
            callback_id = payload["view"]["callback_id"]
            if callback_id == "create_repo_form":
                return handle_repo_form_submission(payload)


    params = parse_qs(request.get_data(as_text=True))
    command = params.get("command", [""])[0]
    text = params.get("text", [""])[0]
    response_url = params.get("response_url", [""])[0]
    user_id = params.get("user_id", [""])[0] 
    print(f"🔐 Checking permission for command `{command}` by user_id: {user_id}")
    print(f"🔐 Allowed user_ids: {COMMAND_PERMISSIONS.get(command)}")
    if command in COMMAND_PERMISSIONS and not has_permission(command, user_id):
        post_to_slack(response_url, f"❌ Sorry <@{user_id}>, you're not authorized to run `{command}`.")
        return make_response("", 200)


    if command == "/jira-report":
        parts = text.strip().split()
        if len(parts) < 2:
            post_to_slack(response_url, "❌ Usage: `/jira-report [issue|repo] <version>`")
            return make_response("", 200)

        subcmd, version = parts[0], parts[1]

        # Optional: Quick feedback to user
        post_to_slack(response_url, f"⏳ Received `/jira-report {subcmd} {version}` from <@{user_id}>. Processing...")

        if subcmd == "issue":
            threading.Thread(target=async_handle_jira_release_issues, args=(version, response_url, user_id)).start()
            return make_response("", 200)
        elif subcmd == "repo":
            threading.Thread(target=async_handle_jira_release_repos, args=(version, response_url, user_id)).start()
            return make_response("", 200)
        else:
            post_to_slack(response_url, "❌ Unknown subcommand. Use `issue` or `repo`.")
            return make_response("", 200)

    elif command == "/test-deploy":
        post_to_slack(response_url, f"⏳ Received /test-deploy {text} from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_test_deploy, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/stage-deploy":
        post_to_slack(response_url, f"⏳ Received /stage-deploy {text} from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_stage_deploy, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/jira-update":
        post_to_slack(response_url, f"⏳ Received `/jira-update` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_jira_status_update, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/create-release-branch":
        post_to_slack(response_url, f"⏳ Received `/create-release-branch {text}` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_create_branch, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/create-repo":
        form = parse_qs(request.get_data(as_text=True))
        trigger_id = form.get("trigger_id", [""])[0]
        return handle_create_repo(trigger_id)
    
    elif command == "/prod-deploy":
        post_to_slack(response_url, f"⏳ Received `/prod-deploy {text}` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_prod_deploy, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/enforce-pr-title-check":
        post_to_slack(response_url, f"⏳ Received `/enforce-pr-title-check` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_enforce_pr_title_check, args=(response_url, user_id)).start()
        return make_response("", 200)
    
    elif command == "/reverse-merge":
        post_to_slack(response_url, f"⏳ Received `/reverse-merge` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_reverse_merge, args=(text, response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/enforce-branch-rules":
        post_to_slack(response_url, f"⏳ Received `/enforce-branch-rules` from <@{user_id}>. Processing...")
        threading.Thread(target=async_handle_enforce_branch_rules, args=(response_url, user_id)).start()
        return make_response("", 200)

    elif command == "/repo-settings":
        if len(text.strip().split()) != 1 or text.strip() not in ["audit", "enforce"]:
            post_to_slack(response_url, "❌ Usage: `/repo-settings <audit|enforce>`")
            return make_response("", 200)
        mode = text.strip()
        threading.Thread(target=async_handle_repo_settings, args=(mode, response_url, user_id)).start()
        return make_response("", 200)

    else:
        return make_response("Unknown command", 400)

def async_handle_jira_release_issues(version, response_url, user_id):
    try:
        handle_jira_release_issues(version, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error: {e}")

def async_handle_jira_release_repos(version, response_url, user_id):
    try:
        handle_jira_release_repos(version, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error: {e}")

def async_handle_jira_status_update(text, response_url, user_id):
    try:
        run_jira_status_update(text, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/jira-update`: {e}")

def async_handle_reverse_merge(text, response_url, user_id):
    try:
        handle_reverse_merge(text, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/reverse-merge`: {e}")


def async_handle_enforce_pr_title_check(response_url, user_id):
    try:
        enforce_pr_title_check(response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/enforce-pr-title-check`: {e}")

def async_handle_test_deploy(text, response_url, user_id):
    try:
        handle_deployment(text, response_url, "release", "develop", user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in /test-deploy: {e}")

def async_handle_stage_deploy(text, response_url, user_id):
    try:
        handle_stage_deployment(text, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in /stage-deploy: {e}")

def async_handle_create_branch(text, response_url, user_id):
    try:
        handle_create_branch(text, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/create-release-branch`: {e}")

def async_handle_enforce_branch_rules(response_url, user_id):
    try:
        enforce_branch_rules(response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/enforce-branch-rules`: {e}")

def async_handle_repo_settings(mode, response_url, user_id):
    try:
        if mode == "audit":
            handle_repo_settings_audit(response_url, user_id)
        elif mode == "enforce":
            handle_repo_settings_enforce(response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/repo-settings {mode}`: {e}")
        print(f"🔥 Exception in repo-settings {mode}: {e}")



def async_handle_prod_deploy(text, response_url, user_id):
    try:
        handle_prod_deploy(text, response_url, user_id)
    except Exception as e:
        post_to_slack(response_url, f"❌ Error in `/prod-deploy`: {e}")


# --- SLACK AUTH ---
def is_valid_slack_request(request):
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    sig_basestring = f"v0:{timestamp}:{request.get_data(as_text=True)}"
    my_sig = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()
    slack_sig = request.headers.get("X-Slack-Signature", "")
    return hmac.compare_digest(my_sig, slack_sig)

# --- SLACK POST ---
def post_to_slack(url, msg):
    requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps({
        "response_type": "in_channel",
        "text": msg
    }))


# ------ WORKFLOW 1: JIRA RELEASE WORKFLOW ---

def handle_jira_release_issues(version, response_url, user_id):
    issues = get_jira_issues(version)
    table_rows = []

    # Build table rows
    for issue in issues:
        key = issue['key']
        summary = issue['summary'][:100]
        status = issue['status']
        assignee = issue['assignee']
        raw_row = f"{key:<10} {status:<25} {assignee:<25} {summary:<100}"
        issue_link = f"<{JIRA_BASE_URL}/browse/{key}|{key}>"
        linked_row = raw_row.replace(key, issue_link, 1)
        table_rows.append(linked_row)

    # Fix version hyperlink (if available)
    version_id = get_jira_version_id(version)
    if version_id:
        version_link = f"<{JIRA_BASE_URL}/projects/{JIRA_PROJECT_KEY}/versions/{version_id}/tab/release-report-all-issues|{version}>"
    else:
        version_link = version

    # Post header message
    post_to_slack(response_url, f"*Command Ran:* `/jira-report issue {version}` by <@{user_id}>\n*📋 Jira Tickets for {version_link}:*")
    time.sleep(1)

    # Format table header
    header = f"{'Key':<10} {'Status':<25} {'Assignee':<25} {'Summary':<100}\n" + "-" * 160 + "\n"

    current_block = header
    for row in table_rows:
        if len(f"```\n{current_block}{row}\n```") > 2900:
            post_to_slack(response_url, f"```\n{current_block}```")
            time.sleep(1)
            current_block = header
        current_block += row + "\n"

    if current_block.strip() != header.strip():
        post_to_slack(response_url, f"```\n{current_block}```")
        time.sleep(1)



def handle_jira_release_repos(version, response_url, user_id):
    issues = get_jira_issues(version)
    repos = set()

    for issue in issues:
        repos.update(get_repos_from_issue(issue["key"]))

    if not repos:
        post_to_slack(response_url, f"*Command Ran:* `/jira-report repo {version}`\n\n*🔗 Repos for `{version}`:*\n_None linked via Jira tickets._")
        return make_response("", 200)

    # Hardcoded "Others"
    others_set = {
        "LearningMotors/kubernetes-manifest",
        "LearningMotors/platform",
        "LearningMotors/protobufs"
    }

    backend, other_services, others = [], [], []

    for repo in sorted(repos):
        if repo in others_set:
            others.append(repo)
        else:
            try:
                topics = get_repo_topics(repo)  # ⬅️ This must be implemented
                if "team-backend" in topics:
                    backend.append(repo)
                else:
                    other_services.append(repo)
            except Exception as e:
                other_services.append(repo)  # fallback if topic fetch fails

    # Version link
    version_id = get_jira_version_id(version)
    if version_id:
        version_link = f"<{JIRA_BASE_URL}/projects/{JIRA_PROJECT_KEY}/versions/{version_id}/tab/release-report-all-issues|{version}>"
    else:
        version_link = version

    # Message format
    msg = f"*Command Ran:* `/jira-report repo {version}` by <@{user_id}>\n\n"
    msg += f"*🔗 Repos for {version_link}:*\n\n"

    if backend:
        msg += "*🛠️ Backend Services:*\n"
        for repo in sorted(backend):
            msg += f"- <https://github.com/{repo}|{repo}>\n"
        msg += "\n"

    if other_services:
        msg += "*🧩 Other Services:*\n"
        for repo in sorted(other_services):
            msg += f"- <https://github.com/{repo}|{repo}>\n"
        msg += "\n"

    if others:
        msg += "*📦 Others:*\n"
        for repo in sorted(others):
            msg += f"- <https://github.com/{repo}|{repo}>\n"

    post_to_slack(response_url, msg.strip())


def get_repo_topics(repo):
    url = f"https://api.github.com/repos/{repo}/topics"
    headers = {
        "Accept": "application/vnd.github.mercy-preview+json",  # needed for topics API
        "Authorization": f"token {GITHUB_TOKEN}"
    }
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    return res.json().get("names", [])


def get_jira_issues(version):
    url = f"{JIRA_BASE_URL}/rest/api/3/search"
    jql = f'project="{JIRA_PROJECT_KEY}" AND fixVersion="{version}"'
    response = requests.get(url, headers=JIRA_HEADERS, params={"jql": jql})
    response.raise_for_status()
    data = response.json()
    return [{
        "key": i["key"],
        "summary": i["fields"]["summary"],
        "status": i["fields"]["status"]["name"],
        "assignee": i["fields"]["assignee"]["displayName"] if i["fields"].get("assignee") else "Unassigned"
    } for i in data.get("issues", [])]


def get_repos_from_issue(issue_key):
    issue_id = get_issue_id(issue_key)
    dev_url = f"{JIRA_BASE_URL}/rest/dev-status/1.0/issue/detail"
    params = {
        "issueId": issue_id,
        "applicationType": "GitHub",
        "dataType": "repository"
    }
    dev_response = requests.get(dev_url, headers=JIRA_HEADERS, params=params)
    dev_response.raise_for_status()
    detail = dev_response.json().get("detail", [])

    repos = set()
    for d in detail:
        for repo in d.get("repositories", []):
            repos.add(repo.get("name"))
    return repos

def get_issue_id(issue_key):
    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}"
    res = requests.get(url, headers=JIRA_HEADERS)
    res.raise_for_status()
    return res.json()["id"]

# --- WORKFLOW 2: TEST DEPLOY WORKFLOW ---
def handle_deployment(text, response_url, branch_from, branch_to, user_id):
    parts = text.strip().split()
    if len(parts) != 2:
        post_to_slack(
            response_url,
            "❌ Usage: `/test-deploy <release_version> <check-mergeability | create-prs | check-status | approve-prs | full>`"
        )
        return

    version, action = parts
    valid_actions = ["check-mergeability", "create-prs", "check-status", "approve-prs", "full"]
    if action not in valid_actions:
        post_to_slack(
            response_url,
            f"❌ Invalid action `{action}`. Valid options are: `check-mergeability`, `create-prs`, `check-status`, `approve-prs`, `full`"
        )
        return

    issues = get_jira_issues(version)
    repo_set = set()
    for issue in issues:
        repo_set.update(get_repos_from_issue(issue["key"]))

    source_branch = f"{branch_from}_{version}"
    # message_lines = [f"*Command Ran:* `/test-deploy {version} {action}` by <@{user_id}>"]
    message_lines = []
    if action != "full":
        message_lines.append(f"*Command Ran:* `/test-deploy {version} {action}` by <@{user_id}>")

    if action == "check-mergeability":
        message_lines.append(f"\n:mag_right: Checking mergeability of `{source_branch}` into `{branch_to}`...\n")

    results_table = []
    merge_results, pr_status, pr_approved = [], [], []

    for repo in sorted(repo_set):
        display_repo = repo
        merge_status = pr_status_result = ci_result = approval_result = ""

        if not branch_exists(repo, source_branch):
            if action in ["check-mergeability", "full"]:
                merge_status = f":warning: `{source_branch}` not found"
                merge_results.append(f":warning: {display_repo} – Branch `{source_branch}` not found")
            if action == "full":
                results_table.append((display_repo, merge_status, "", "", ""))
            continue

        # MERGE CHECK
        if action in ["check-mergeability", "full"]:
            if is_release_branch_behind(repo, branch_to, source_branch):
                merge_status = f"⚠️ behind `{branch_to}`"
                merge_results.append(f"⚠️ {display_repo} – `{source_branch}` is behind `{branch_to}`")
            else:
                merge_status = f"✅ up-to-date with `{branch_to}`"
                merge_results.append(f"✅ {display_repo} – `{source_branch}` is up-to-date with `{branch_to}`")

        pr = None
        created_now = False
        pr_link = ""

        # PR CREATION
        if action in ["create-prs", "check-status", "approve-prs", "full"]:
            if not has_commits_between(repo, branch_to, source_branch):
                pr_status_result = ":warning: No commits (PR skipped)"
                if action in ["create-prs", "full"]:
                    merge_results.append(f":warning: {display_repo} – No commits between `{source_branch}` and `{branch_to}` (PR skipped)")
                if action == "full":
                    results_table.append((display_repo, merge_status, pr_status_result, "", ""))
                continue

            existing_pr = find_existing_pr(repo, source_branch, branch_to)
            if existing_pr:
                pr = existing_pr
            else:
                pr = create_pr(repo, source_branch, branch_to)
                if not pr:
                    pr_status_result = "❌ Failed to create PR"
                    merge_results.append(f"❌ {display_repo} – Failed to create PR")
                    if action == "full":
                        results_table.append((display_repo, merge_status, pr_status_result, "", ""))
                    continue
                created_now = True

            pr_url = pr["html_url"]
            pr_api_url = pr["url"]
            pr_link = f"<{pr_url}|{display_repo}>"

            if action in ["create-prs", "full"]:
                if check_mergeability(pr_api_url):
                    pr_status_result = "✅ Mergeable"
                    pr_summary = f"<{pr_url}|{display_repo}>"
                    if created_now:
                        merge_results.append(f"✅ {display_repo} – PR created and is mergeable ({pr_summary})")
                    else:
                        merge_results.append(f"✅ {display_repo} – PR exists and is mergeable ({pr_summary})")
                else:
                    pr_status_result = ":x: Merge conflicts"
                    merge_results.append(f":x: {display_repo} – PR has merge conflicts")

        # CI STATUS
        sha = None
        passed = False
        if action in ["check-status", "approve-prs", "full"] and pr:
            sha = get_latest_commit_sha(repo, source_branch)
            if sha:
                passed, ci_debug = check_pr_status(repo, sha)
                if passed:
                    ci_result = "✅ Passed"
                    if action in ["check-status", "full"]:
                        pr_status.append(f"- {pr_link} ✅ CI passed")
                else:
                    ci_result = "❌ Failed"
                    if action in ["check-status", "full"]:
                        pr_status.append(f"- {pr_link} ❌ CI failed")
                        pr_status.append(f"```{json.dumps(ci_debug, indent=2)[:3000]}```")
                    if action in ["approve-prs", "full"]:
                        approval_result = "❌ Skipped (CI failed)"

        # PR APPROVAL
        if action in ["approve-prs", "full"] and pr and sha and passed:
            if check_mergeability(pr_api_url) and approve_pr(repo, pr_url):
                approval_result = "✅ Approved"
                pr_approved.append(pr_link)
            else:
                approval_result = "❌ Approval failed"
                pr_approved.append(f"- {pr_link} ❌ Approval failed or PR not mergeable")

        if action == "full":
            results_table.append((display_repo, merge_status, pr_status_result, ci_result, approval_result))

    if not repo_set:
        message_lines.append("_No repositories linked to this Jira release._")
    elif not merge_results and action == "check-mergeability":
        message_lines.append("_No release branches found for mergeability check._")

    # Output logic
    if action == "full":
        post_to_slack(response_url, f"*Command Ran:* /test-deploy {version} {action} by <@{user_id}>")
        post_to_slack(response_url, ":bar_chart: *Test Deploy Summary Table:*")
        # Post header
        header = f"{'Repository':<40} {'Merge':<30} {'PR Status':<25} {'CI Status':<15} {'Approval':<15}\n" + "-" * 130 + "\n"
        block = header
        for row in results_table:
            line = f"{row[0]:<40} {row[1]:<30} {row[2]:<25} {row[3]:<15} {row[4]:<15}\n"
            if len(f"```\n{block}{line}```") > 2800:
                post_to_slack(response_url, f"```\n{block}```")
                block = header
            block += line
        if block.strip() != header.strip():
            post_to_slack(response_url, f"```\n{block}```")
    else:
        if merge_results and action in ["check-mergeability", "create-prs"]:
            message_lines.append("\n*🧪 Merge Check & PR Results:*")
            message_lines.extend(merge_results)

        if pr_status and action in ["check-status", "approve-prs"]:
            message_lines.append("\n*🔬 PR Build Status:*")
            message_lines.extend(pr_status)

        if pr_approved and action in ["approve-prs"]:
            message_lines.append("\n*✅ Approved PRs:*")
            message_lines.extend(pr_approved)

    if not any([merge_results, pr_status, pr_approved]) and repo_set and action != "full":
        message_lines.append("\n_No relevant updates for this command._")

    post_to_slack(response_url, "\n".join(message_lines).strip())
    return 



# ---WORKFLOW 3: STAGE DEPLOY----

def handle_stage_deployment(text, response_url, user_id):
    try:
        parts = text.strip().split()
        if len(parts) != 2:
            post_to_slack(
                response_url,
                "❌ Usage: `/stage-deploy <release_version> <check-mergeability | create-prs | check-status | approve-prs | full>`"
            )
            return 

        version, action = parts
        valid_actions = ["check-mergeability", "create-prs", "check-status", "approve-prs", "full"]
        if action not in valid_actions:
            post_to_slack(
                response_url,
                f"❌ Invalid action `{action}`. Valid options: `check-mergeability`, `create-prs`, `check-status`, `approve-prs`, `full`"
            )
            return 

        branch_from = "develop"
        issues = get_jira_issues(version)
        repo_set = set()
        for issue in issues:
            repo_set.update(get_repos_from_issue(issue["key"]))

        message_lines = [f"*Command Ran:* `/stage-deploy {version} {action}` by <@{user_id}>"]

        if action == "check-mergeability":
            message_lines.append(f"\n:mag_right: Checking mergeability of `{branch_from}` into `main`/`master`...\n")

        table_rows = []
        merge_results, pr_status, pr_approved = {}, {}, {}

        for repo in sorted(repo_set):
            display_repo = repo
            merge_col = pr_col = status_col = approve_col = ""

            try:
                branch_to = get_main_or_master_branch(repo)
            except Exception as e:
                merge_col = str(e)
                if action != "full":
                    message_lines.append(f":warning: {display_repo} – {str(e)}")
                table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                continue

            if not branch_exists(repo, branch_from):
                merge_col = f":warning: Branch `{branch_from}` not found"
                if action != "full":
                    message_lines.append(f":warning: {display_repo} – Branch `{branch_from}` not found")
                table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                continue

            if action in ["check-mergeability", "full"]:
                if is_release_branch_behind(repo, branch_to, branch_from):
                    merge_col = f"⚠️ Behind `{branch_to}`"
                else:
                    merge_col = f"✅ Up-to-date"
                if action != "full":
                    message_lines.append(f"{merge_col} – {display_repo}")

            pr = None
            created_now = False
            if action in ["create-prs", "check-status", "approve-prs", "full"]:
                if not has_commits_between(repo, branch_to, branch_from):
                    pr_col = ":warning: No commits (PR skipped)"
                    if action in ["create-prs", "full"] and action != "full":
                        message_lines.append(f"{display_repo} – {pr_col}")
                    table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                    continue

                existing_pr = find_existing_pr(repo, branch_from, branch_to)
                if existing_pr:
                    pr = existing_pr
                else:
                    pr = create_pr(repo, branch_from, branch_to)
                    if not pr:
                        pr_col = "❌ PR creation failed"
                        if action != "full":
                            message_lines.append(f"{display_repo} – {pr_col}")
                        table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                        continue
                    created_now = True

                pr_url = pr["html_url"]
                pr_api_url = pr["url"]
                pr_link = f"<{pr_url}|PR>"

                if check_mergeability(pr_api_url):
                    pr_col = f"✅ {('Created' if created_now else 'Exists')} & mergeable"
                else:
                    pr_col = ":x: Merge conflicts"
                if action in ["create-prs", "full"] and action != "full":
                    message_lines.append(f"{display_repo} – {pr_col}")

            sha = None
            passed = False
            if action in ["check-status", "approve-prs", "full"] and pr:
                sha = get_latest_commit_sha(repo, branch_from)
                if sha:
                    passed, ci_debug = check_pr_status(repo, sha)
                    if passed:
                        status_col = "✅ Passed"
                        if action == "check-status":
                            message_lines.append(f"- {pr_link} ✅ CI passed")

                    else:
                        status_col = "❌ Failed"
                        if action == "check-status":
                            message_lines.append(f"- {pr_link} ❌ CI failed\n```{json.dumps(ci_debug, indent=2)[:3000]}```")

            if action in ["approve-prs", "full"] and pr and sha and passed:
                if check_mergeability(pr_api_url) and approve_pr(repo, pr_url):
                    approve_col = "✅ Approved"
                else:
                    approve_col = "❌ Approval failed"
                if action != "full":
                    message_lines.append(f"{display_repo} – {approve_col}")

            table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))

        if action == "full":
            post_to_slack(response_url, "\n".join(message_lines)) 
            
            header = f"{'Repository':<45} {'Merge Status':<20} {'PR':<30} {'CI Status':<15} {'Approval':<15}\n" + "-" * 130 + "\n"
            current_block = header
            for row in table_rows:
                line = f"{row[0]:<45} {row[1]:<20} {row[2]:<30} {row[3]:<15} {row[4]:<15}\n"
                if len(f"```\n{current_block}{line}```") > 2900:
                    post_to_slack(response_url, f"```\n{current_block}```")
                    time.sleep(1)
                    current_block = header
                current_block += line
            if current_block.strip() != header.strip():
                post_to_slack(response_url, f"```\n{current_block}```")
        else:
            if not repo_set:
                message_lines.append("_No repositories linked to this Jira release._")
            elif not table_rows:
                message_lines.append("_No updates for this action._")
            post_to_slack(response_url, "\n".join(message_lines).strip())

        return 

    except Exception as e:
        post_to_slack(response_url, f"❌ Error running `/stage-deploy`: ```{str(e)}```")
        return 


# --- WORKFLOW 4 : PRODUCTION DEPLOYMENT ---

def handle_prod_deploy(release_version, response_url, user_id):
    post_to_slack(response_url, f":hourglass: Starting `/prod-deploy {release_version}`...")

    manifest_repo = "LearningMotors/kubernetes-manifest"
    pr_links = []
    warnings = []

    # 🔍 Fetch all repos under the fixVersion
    issues = get_jira_issues(release_version)
    all_repos = set()
    for issue in issues:
        all_repos.update(get_repos_from_issue(issue["key"]))

    # Hard skip infra repos
    skip_repos = {"LearningMotors/kubernetes-manifest", "LearningMotors/protobufs", "LearningMotors/platform"}

    for repo in sorted(all_repos):
        if repo in skip_repos:
            continue

        service = repo.split("/")[-1]

        try:
            main_branch = get_main_or_master_branch_strict(repo)
            if not main_branch:
                warnings.append(f":x: {service} – No `main` or `master` branch found.")
                continue
        except Exception as e:
            warnings.append(f":x: {service} – No `main` or `master` branch found.")
            continue

        latest_sha = get_latest_commit_sha(repo, main_branch)
        if not latest_sha:
            warnings.append(f":x: {service} – Failed to get latest commit from `{main_branch}`.")
            continue

        branch_name = f"prod-release/{release_version}-{service}"
        base_branch = "main"
        base_sha = get_latest_commit_sha(manifest_repo, base_branch)
        if not base_sha:
            warnings.append(f":x: {service} – Failed to fetch base SHA for `{base_branch}` in manifest.")
            continue

        if not create_branch(manifest_repo, branch_name, base_sha):
            warnings.append(f":x: {service} – Failed to create branch `{branch_name}` in `{manifest_repo}`.")
            continue

        file_path = f"{service}/overlays/prod/image-patch.yaml"
        file_data = get_file_content(manifest_repo, file_path, base_branch)
        if not file_data:
            warnings.append(f":x: {service} – Failed to fetch `image-patch.yaml` from `{base_branch}`.")
            continue

        original_content = file_data["decoded"]
        sha = file_data["sha"]
        short_sha = latest_sha[:7]

        updated_content = update_image_patch_yaml(original_content, service, main_branch, short_sha)
        if not updated_content:
            warnings.append(f":x: {service} – Failed to update `image-patch.yaml` content.")
            continue

        # 🔐 Try to fetch Jira issue key for PR title
        jira_key = "BAC-000"
        jira_version_id = get_jira_version_id(release_version)
        if jira_version_id:
            url = f"{JIRA_BASE_URL}/rest/api/3/search"
            jql = f'project = {JIRA_PROJECT_KEY} AND fixVersion = {jira_version_id}'
            res = requests.get(url, headers=JIRA_HEADERS, params={"jql": jql})
            if res.status_code == 200 and res.json().get("issues"):
                jira_key = res.json()["issues"][0]["key"]

        commit_message = f"{jira_key} - Prod deploy: {release_version} for {service}"
        if not commit_file_change(manifest_repo, file_path, updated_content, commit_message, branch_name, sha):
            warnings.append(f":x: {service} – Failed to commit updated `image-patch.yaml`.")
            continue

        pr_url = open_pr_in_manifest(manifest_repo, branch_name, service, latest_sha, release_version, commit_message)
        if pr_url:
            pr_links.append(f"• {service} → {pr_url}")
        else:
            warnings.append(f":x: {service} – Failed to open PR for `{branch_name}`.")

    # Compose final message
    msg = f"*Command Ran:* `/prod-deploy {release_version}` by <@{user_id}>\n\n"
    if pr_links:
        msg += ":rocket: *Prod Kubernetes PRs:*\n" + "\n".join(pr_links) + "\n\n"
    if warnings:
        msg += ":warning: *Issues Encountered:*\n" + "\n".join(warnings)

    post_to_slack(response_url, msg.strip())

# ------ WORFLOW 5   handle_reverse_merge -----

def handle_reverse_merge(text, response_url, user_id):
    try:
        parts = text.strip().split()
        if len(parts) != 3:
            post_to_slack(
                response_url,
                "❌ Usage: `/reverse-merge [main-to-develop | develop-to-release] <release-version> <check-mergeability | create-prs | check-status | approve-prs | full>`"
            )
            return

        direction, version, action = parts
        valid_directions = ["main-to-develop", "develop-to-release"]
        valid_actions = ["check-mergeability", "create-prs", "check-status", "approve-prs", "full"]

        if direction not in valid_directions:
            post_to_slack(response_url, f"❌ Invalid direction `{direction}`. Use `main-to-develop` or `develop-to-release`.")
            return

        if action not in valid_actions:
            post_to_slack(
                response_url,
                f"❌ Invalid action `{action}`. Valid options: `check-mergeability`, `create-prs`, `check-status`, `approve-prs`, `full`"
            )
            return 

        if direction == "main-to-develop":
            branch_from = "main"
            branch_to = "develop"
        else:
            branch_from = "develop"
            branch_to = f"release_{version}"

        issues = get_jira_issues(version)
        repo_set = set()
        for issue in issues:
            repo_set.update(get_repos_from_issue(issue["key"]))

        message_lines = [f"*Command Ran:* `/reverse-merge {direction} {version} {action}` by <@{user_id}>"]
        if action == "check-mergeability":
            message_lines.append(f"\n:mag_right: Checking mergeability of `{branch_from}` into `{branch_to}`...\n")

        table_rows = []
        merge_results, pr_status, pr_approved = [], [], []

        for repo in sorted(repo_set):
            display_repo = repo
            merge_col = pr_col = status_col = approve_col = ""

            if not branch_exists(repo, branch_from) or not branch_exists(repo, branch_to):
                merge_col = f":warning: Missing `{branch_from}` or `{branch_to}`"
                if action != "full":
                    message_lines.append(f":warning: {display_repo} – {merge_col}")
                table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                continue

            if action in ["check-mergeability", "full"]:
                from_to = has_commits_between(repo, branch_from, branch_to)
                to_from = has_commits_between(repo, branch_to, branch_from)

                if from_to and to_from:
                    merge_col = f"⚠️ Diverged (PR may be mergeable)"
                elif from_to:
                    merge_col = f"✅ Reverse merge needed"
                elif to_from:
                    merge_col = f"🔁 No reverse needed"
                else:
                    merge_col = f"✅ Identical"

                if action != "full":
                    message_lines.append(f"{merge_col} – {display_repo}")

            pr = None
            created_now = False
            pr_link = ""

            if action in ["create-prs", "check-status", "approve-prs", "full"]:
                if not has_commits_between(repo, branch_to, branch_from):
                    pr_col = ":warning: No commits (PR skipped)"
                    if action in ["create-prs"] and action != "full":
                        message_lines.append(f"{display_repo} – {pr_col}")
                    table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                    continue

                existing_pr = find_existing_pr(repo, branch_from, branch_to)
                if existing_pr:
                    pr = existing_pr
                else:
                    pr = create_pr(repo, branch_from, branch_to)
                    if not pr:
                        pr_col = "❌ PR creation failed"
                        if action != "full":
                            message_lines.append(f"{display_repo} – {pr_col}")
                        table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))
                        continue
                    created_now = True

                pr_url = pr["html_url"]
                pr_api_url = pr["url"]
                pr_link = f"<{pr_url}|PR>"

                if check_mergeability(pr_api_url):
                    pr_col = f"✅ {'Created' if created_now else 'Exists'} & mergeable → {pr_link}"
                else:
                    pr_col = f":x: Merge conflicts → {pr_link}"

                if action == "create-prs" and action != "full":
                    message_lines.append(f"{display_repo} – {pr_col}")

            sha = None
            passed = False
            if action in ["check-status", "approve-prs", "full"] and pr:
                sha = get_latest_commit_sha(repo, branch_from)
                if sha:
                    passed, ci_debug = check_pr_status(repo, sha)
                    if passed:
                        status_col = "✅ Passed"
                        if action == "check-status":
                            message_lines.append(f"- {pr_link} ✅ CI passed")
                    else:
                        status_col = "❌ Failed"
                        if action == "check-status":
                            message_lines.append(f"- {pr_link} ❌ CI failed\n```{json.dumps(ci_debug, indent=2)[:3000]}```")

            if action in ["approve-prs", "full"] and pr and sha and passed:
                if check_mergeability(pr_api_url) and approve_pr(repo, pr_url):
                    approve_col = "✅ Approved"
                else:
                    approve_col = "❌ Approval failed"
                if action != "full":
                    message_lines.append(f"{display_repo} – {approve_col}")

            table_rows.append((display_repo, merge_col, pr_col, status_col, approve_col))

        # Output logic
        if not repo_set:
            post_to_slack(response_url, "_No repositories linked to this Jira release._")
            return

        if action == "full":
            post_to_slack(response_url, "\n".join(message_lines))
            header = f"{'Repository':<45} {'Merge Status':<45} {'PR':<30} {'CI Status':<20} {'Approval':<25}\n" + "-" * 160 + "\n"
            current_block = header
            for row in table_rows:
                line = f"{row[0]:<45} {row[1]:<45} {row[2]:<30} {row[3]:<20} {row[4]:<25}\n"
                if len(f"```\n{current_block}{line}```") > 2900:
                    post_to_slack(response_url, f"```\n{current_block}```")
                    time.sleep(1)
                    current_block = header
                current_block += line
            if current_block.strip() != header.strip():
                post_to_slack(response_url, f"```\n{current_block}```")

        else:
            if not table_rows:
                message_lines.append("_No updates for this action._")
            post_to_slack(response_url, "\n".join(message_lines).strip())

        return

    except Exception as e:
        post_to_slack(response_url, f"❌ Error running `/reverse-merge`: ```{str(e)}```")
        return



# --- WORKFLOW 6: JIRA STATUS UPDATE ---
def run_jira_status_update(text, response_url, user_id):
    parts = text.strip().split()
    if len(parts) != 3 or parts[0] not in ["status", "transition"] or parts[1] not in ["develop", "main"]:
        post_to_slack(response_url, "❌ Usage: `/jira-update [status|transition] [develop|main] <release_version>`")
        return

    mode, target_branch, version = parts

    rules = {
        "develop": {
            "required": "Development Done",
            "transition_to": "Ready for QA Test"
        },
        "main": {
            "required": "Passed QA Test",
            "transition_to": "Ready for QA Stage"
        }
    }[target_branch]

    issues = get_jira_issues(version)

    # Result buckets
    eligible, ineligible, skipped, updated, warned = [], [], [], [], []

    for issue in issues:
        key = issue["key"]
        current_status = issue["status"]
        issue_link = f"<{JIRA_BASE_URL}/browse/{key}|{key}>"

        # Check PRs
        prs = get_prs_from_issue(key)
        merged_to_target = any(pr["merged"] and pr["base"] == target_branch for pr in prs)

        if not merged_to_target:
            msg = f"• {issue_link} – PR not merged to `{target_branch}`"
            skipped.append(msg)
            continue

        if current_status == rules["required"]:
            if mode == "status":
                eligible.append(f"• {issue_link} – ✅ Ready to move to *{rules['transition_to']}*")
            else:
                success = update_jira_status(key, rules["transition_to"])
                if success:
                    updated.append(f"• {issue_link} → ✅ {rules['transition_to']}")
                else:
                    warned.append(f"• {issue_link} → ❌ Failed to update Jira status")
        else:
            msg = f"• {issue_link} – ❌ Status is *'{current_status}'*, expected *'{rules['required']}'*"
            if mode == "status":
                ineligible.append(msg)
            else:
                warned.append(f"• {issue_link} → :warning: Not updated: {msg}")

    # Compose message
    msg = f"*Command Ran:* `/jira-update {mode} {target_branch} {version}` by <@{user_id}>\n\n"
    if mode == "status":
        msg += f":mag: *Jira Ticket Status Check for `{version}` on `{target_branch}`*\n\n"
        if eligible:
            msg += "*✅ Eligible:*\n" + "\n".join(eligible) + "\n\n"
        if ineligible:
            msg += "*❌ Ineligible:*\n" + "\n".join(ineligible) + "\n\n"
        if skipped:
            msg += "*:double_vertical_bar: Skipped (No PR merged to this branch):*\n" + "\n".join(skipped) + "\n"
    else:
        msg += f":recycle: *Transition Summary for `{version}` on `{target_branch}`*\n\n"
        if updated:
            msg += "*✅ Updated:*\n" + "\n".join(updated) + "\n\n"
        if warned:
            msg += "*:warning: Warnings:*\n" + "\n".join(warned) + "\n\n"
        if skipped:
            msg += "*:double_vertical_bar: Skipped (No PR merged to this branch):*\n" + "\n".join(skipped) + "\n"

    post_to_slack(response_url, msg.strip())



def get_prs_from_issue(issue_key):
    url = f"{JIRA_BASE_URL}/rest/dev-status/1.0/issue/detail"
    params = {
        "issueId": get_issue_id(issue_key),
        "applicationType": "GitHub",
        "dataType": "pullrequest"
    }
    response = requests.get(url, headers=JIRA_HEADERS, params=params)
    response.raise_for_status()
    detail = response.json().get("detail", [])
    
    prs = []
    for d in detail:
        for pr in d.get("pullRequests", []):
            prs.append({
                "url": pr.get("url"),
                "merged": pr.get("status") == "MERGED",
                "base": pr.get("destination", {}).get("branch"),
                "status_raw": pr.get("status"),
                "title": pr.get("title")
            })
    
    print(f"🔍 PRs for issue {issue_key}: {json.dumps(prs, indent=2)}")
    return prs


def update_jira_status(issue_key, target_status):
    transitions_url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/transitions"
    transitions = requests.get(transitions_url, headers=JIRA_HEADERS).json().get("transitions", [])
    transition_id = next((t["id"] for t in transitions if t["to"]["name"].lower() == target_status.lower()), None)
    if not transition_id:
        return False
    res = requests.post(transitions_url, headers=JIRA_HEADERS, json={"transition": {"id": transition_id}})
    return res.status_code == 204

# --- WORKFLOW 7: CREATE BRANCH ---
def handle_create_branch(text, response_url,user_id):
    parts = text.strip().split()
    if not parts:
        post_to_slack(response_url, "❌ Usage: `/create-release-branch <version> [repo1,repo2,...]`")
        return make_response("", 200)

    version = parts[0]
    requested_repos = []
    if len(parts) > 1:
        requested_repos = [f"LearningMotors/{r.strip()}" for r in parts[1].split(",") if r.strip()]

    # Fetch Jira issues and linked repos
    issues = get_jira_issues(version)
    linked_repos = set()
    for issue in issues:
        linked_repos.update(get_repos_from_issue(issue["key"]))

    # Validate requested repos (if any)
    if requested_repos:
        invalid = [r for r in requested_repos if r not in linked_repos]
        if invalid:
            post_to_slack(response_url, f"❌ The following repos are not linked to version `{version}` via Jira:\n• " + "\n• ".join(invalid))
            return make_response("", 200)
        repos_to_process = sorted(requested_repos)
    else:
        repos_to_process = sorted(linked_repos)

    # Start Slack message
    msg = f"*Command Ran:* `/create-release-branch {version}` by <@{user_id}>"
    if requested_repos:
        cleaned_names = [r.split('/')[-1] for r in requested_repos]
        msg += f" {', '.join(cleaned_names)}"

    branch_url = f"https://github.com/LearningMotors/release-automation-test/tree/release_{version}"
    msg += f"`\n\n🌿 *Release Branch Creation: <{branch_url}|release_{version}>*\n\n"

    
    version_branch = f"release_{version}"
    base_branch = "develop"

    for repo in repos_to_process:
        if branch_exists(repo, version_branch):
            msg += f"✅ {repo} → `{version_branch}` already exists\n"
            continue

        sha = get_latest_commit_sha(repo, base_branch)
        if not sha:
            msg += f"❌ {repo} → Failed to fetch `{base_branch}` SHA\n"
            continue

        created = create_branch(repo, version_branch, sha)
        if not created:
            msg += f"❌ {repo} → Failed to create `{version_branch}`\n"
            continue

        mergeable = is_release_branch_behind(repo, base_branch, version_branch)
        if mergeable is False:
            msg += f"⚠️ {repo} → Conflict detected: `{base_branch}` ↔ `{version_branch}`\n"
        else:
            msg += f"✅ {repo} → `{version_branch}` created from `{base_branch}`\n"

    post_to_slack(response_url, msg)
    return 



# --- WORKFLOW 8: CREATE REPO ---
# --- WORKFLOW 8: CREATE REPO ---
def handle_create_repo(trigger_id):
    modal_view = build_create_repo_modal()
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "trigger_id": trigger_id,
        "view": modal_view
    }
    response = requests.post("https://slack.com/api/views.open", headers=headers, json=payload)
    if not response.ok or not response.json().get("ok"):
        print("Error opening modal:", response.text)
    return make_response("", 200)

def build_create_repo_modal():
    return {
        "type": "modal",
        "callback_id": "create_repo_form",
        "title": {"type": "plain_text", "text": "Create New GitHub Repo"},
        "submit": {"type": "plain_text", "text": "Create"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "input",
                "block_id": "repo_name_block",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "repo_name",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "e.g., payment-service"
                    }
                },
                "label": {
                    "type": "plain_text",
                    "text": "Repository Name"
                }
            },
            {
                "type": "input",
                "block_id": "team_block",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "team_name",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "e.g., backend-devs"
                    }
                },
                "label": {
                    "type": "plain_text",
                    "text": "Team to Grant Access"
                }
            },
            {
                "type": "input",
                "block_id": "permission_block",
                "element": {
                    "type": "static_select",
                    "action_id": "permission_level",
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Admin"},
                            "value": "admin"
                        },
                        {
                            "text": {"type": "plain_text", "text": "Maintain"},
                            "value": "maintain"
                        },
                        {
                            "text": {"type": "plain_text", "text": "Write"},
                            "value": "write"
                        }
                    ]
                },
                "label": {
                    "type": "plain_text",
                    "text": "Team Permission Level"
                }
            },
            {
                "type": "input",
                "block_id": "topics_block",
                "optional": True,
                "element": {
                    "type": "plain_text_input",
                    "action_id": "topics",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Comma-separated, e.g., backend,nodejs,api"
                    }
                },
                "label": {
                    "type": "plain_text",
                    "text": "Topics (for GitHub)"
                }
            },
            {
                "type": "section",
                "block_id": "ci_cd_block",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Setup Options*"
                },
                "accessory": {
                    "type": "checkboxes",
                    "action_id": "setup_options",
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Add PR checks (Codecov, Security, Lint)"},
                            "value": "pr_checks"
                        },
                        {
                            "text": {"type": "plain_text", "text": "Add Cloud Build + Dockerfile"},
                            "value": "cloud_build"
                        },
                        {
                            "text": {"type": "plain_text", "text": "Set up Cloud Build Trigger"},
                            "value": "cloud_build_trigger"
                        },
                        {
                            "text": {"type": "plain_text", "text": "Raise k8s manifest PR"},
                            "value": "k8s_manifest"
                        }
                    ]
                }
            }
        ]
    }


def handle_repo_form_submission(payload):
    import re

    user = payload["user"]["username"]
    values = payload["view"]["state"]["values"]

    repo_name = values["repo_name_block"]["repo_name"]["value"]

        # Enforce lowercase + hyphenated repo names
    if not re.match(r"^[a-z0-9\-]+$", repo_name.lower()):
        return {
            "response_action": "errors",
            "errors": {
                "repo_name_block": "❌ Repo name must be lowercase, and contain only letters, numbers, and hyphens (e.g. `my-service`)"
            }
        }

    team_name = values["team_block"]["team_name"]["value"]
    permission_level = values["permission_block"]["permission_level"]["selected_option"]["value"]

    topics_raw = values.get("topics_block", {}).get("topics", {}).get("value", "")
    topics = [t.strip() for t in topics_raw.split(",") if t.strip()]

    setup_options = []
    selected_options = values.get("ci_cd_block", {}).get("setup_options", {}).get("selected_options", [])
    if selected_options:
        setup_options = [item["value"] for item in selected_options]

    # ✅ Run repo creation in background thread
    threading.Thread(target=create_github_repo, kwargs={
        "repo_name": repo_name,
        "team": team_name,
        "permission": permission_level,
        "topics": topics,
        "setup_options": setup_options,
        "requested_by": user,
        "response_url": None
    }).start()

    # ✅ Return empty JSON quickly to Slack
    return jsonify({})  # instead of make_response("", 200)


def create_github_repo(repo_name, team, permission, topics, setup_options, requested_by,response_url=None):
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    org = "LearningMotors"

    # Step 1: Create the repo
    repo_payload = {
        "name": repo_name,
        "description": f"Repository created by {requested_by} via Slack",
        "private": True,
        "has_issues": True,
        "has_projects": False,
        "has_wiki": False,
        "auto_init": True
    }

    repo_res = requests.post(
        f"https://api.github.com/orgs/{org}/repos",
        headers=headers,
        json=repo_payload
    )

    if not repo_res.ok:
        print("❌ Failed to create repo:", repo_res.text)
        return

    # Step 2: Set topics
    if topics:
        topic_res = requests.put(
            f"https://api.github.com/repos/{org}/{repo_name}/topics",
            headers={**headers, "Accept": "application/vnd.github.mercy-preview+json"},
            json={"names": topics}
        )
        if not topic_res.ok:
            print("⚠️ Failed to set topics:", topic_res.text)

    # Step 3: Add team access with permissions
    team_res = requests.put(
        f"https://api.github.com/orgs/{org}/teams/{team}/repos/{org}/{repo_name}",
        headers=headers,
        json={"permission": permission}
    )
    if not team_res.ok:
        print("⚠️ Failed to grant team access:", team_res.text)

    # Step 4: Setup CI / Build / k8s options
    if "pr_checks" in setup_options:
        setup_pr_checks(org, repo_name)

    if "cloud_build" in setup_options:
        setup_cloudbuild_files(org, repo_name)

    if "cloud_build_trigger" in setup_options:
        setup_cloudbuild_trigger(org, repo_name)

    if "k8s_manifest" in setup_options:
        raise_k8s_manifest_pr(org, repo_name)

    print(f"✅ Repo '{repo_name}' created and configured successfully.")

    if response_url:
        slack_msg = (
            f"✅ Repo <https://github.com/LearningMotors/{repo_name}|{repo_name}> created by *{requested_by}*\n"
            f"*Team:* `{team}`\n"
            f"*Permission:* `{permission}`\n"
            f"*Topics:* {', '.join(topics) if topics else 'None'}\n"
            f"*Files Added:* "
            f"{'PR Checks ✅' if 'pr_checks' in setup_options else ''} "
            f"{'Cloud Build ✅' if 'cloud_build' in setup_options else ''} "
            f"{'Build Trigger ✅' if 'cloud_build_trigger' in setup_options else ''} "
            f"{'K8s PR ✅' if 'k8s_manifest' in setup_options else ''}"
            ).strip()
        post_to_slack(response_url, slack_msg)
    


def setup_pr_checks(org, repo):

    ci_content = read_template("github/workflows/github_ci.yml")
    validate_pr_title = read_template("github/workflows/validate_pr_title.yml")

    upload_file_to_repo(org, repo, ".github/workflows/github_ci.yml", ci_content, "Add GitHub CI workflow")
    upload_file_to_repo(org, repo, ".github/workflows/validate_pr_title.yml", validate_pr_title, "Add PR title validation workflow")


def setup_cloudbuild_files(org, repo):

    dockerfile = read_template("Dockerfile")
    cloudbuild_yaml = read_template("cloudbuild.yaml")

    upload_file_to_repo(org, repo, "Dockerfile", dockerfile, "Add Dockerfile")
    upload_file_to_repo(org, repo, "cloudbuild.yaml", cloudbuild_yaml, "Add Cloud Build config")

def setup_cloudbuild_trigger(org, repo):
    # Simulate trigger setup — normally you'd use Google Cloud Build API
    print(f"🛠️ Would set up Cloud Build trigger for {repo}")

def upload_file_to_repo(org, repo, path, content, message, branch="main"):
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    encoded = b64encode(content.encode()).decode()
    res = requests.put(
        f"https://api.github.com/repos/{org}/{repo}/contents/{path}",
        headers=headers,
        json={
            "message": message,
            "content": encoded,
            "branch": branch
        }
    )
    if not res.ok:
        print(f"⚠️ Failed to upload {path}:", res.text)
        return False
    return True







# --- Helper: Upload Files to GitHub Repo ---
def upload_to_repo(repo_name, path, content, branch="main"):
    url = f"https://api.github.com/repos/{repo_name}/contents/{path}"
    payload = {
        "message": f"Add {path}",
        "content": b64encode(content.encode()).decode(),
        "branch": branch
    }
    res = requests.put(url, headers=HEADERS_GITHUB, json=payload)
    return res.status_code in [200, 201]


# --- WORKFLOW 10 enforce_pr_title_check ----

def enforce_pr_title_check(response_url, user_id):
    ORG = "LearningMotors"
    BRANCH_NAME = "add-pr-title-check"
    FILE_PATH = ".github/workflows/validate_pr_title.yml"
    PR_TITLE = "Add PR Title Validation Workflow"
    PR_BODY = "This PR adds a GitHub Action to enforce PR title formatting."

    # ✅ Fixed: Regex + safe shell usage via env
    validate_pr_title_yml = """
name: Validate PR Title

on:
  pull_request:
    types: [opened, edited, synchronize]

permissions:
  contents: read

jobs:
  check-title:
    name: Check PR Title Format
    runs-on: ubuntu-latest
    if: "!contains(github.head_ref, 'add-pr-title-check')" # 👈 skip branch named add-pr-title-check
    steps:
      - name: Validate PR title format
        shell: bash
        run: |
          echo "🔍 Validating PR title: $TITLE"
          if [[ ! $TITLE =~ ^[A-Z]+-[0-9]+\ \-\ .+ ]]; then
            echo "❌ PR title must match format: ABC-123 - Your title"
            echo "✅ Example: SRE-21 - Enforce Jira ID checks"
            exit 1
          else
            echo "✅ PR title format is valid: $TITLE"
          fi
        env:
          TITLE: ${{ github.event.pull_request.title }}
"""

    repos_with_check = []
    repos_missing_check = []
    prs_created = []

    # Step 1: List all repos in the org
    repos = []
    for page in range(1, 6):  # Adjust to max pages needed
        url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page={page}"
        res = requests.get(url, headers=HEADERS_GITHUB)
        if res.status_code == 200:
            page_repos = res.json()
            if not page_repos:
                break
            repos.extend(page_repos)
        else:
            print(f"❌ Failed to fetch repos on page {page}")
            break

    for repo in repos:
        name = repo["name"]
        full_name = repo["full_name"]

        # Step 2: Filter by topics
        topic_url = f"https://api.github.com/repos/{full_name}/topics"
        topic_res = requests.get(topic_url, headers={**HEADERS_GITHUB, "Accept": "application/vnd.github.mercy-preview+json"})
        topics = topic_res.json().get("names", []) if topic_res.status_code == 200 else []

        if "production-true" in topics and "team-backend" in topics:
            # Step 3: Check if workflow file already exists
            default_branch = get_default_branch(full_name)
            file_check_url = f"https://api.github.com/repos/{full_name}/contents/{FILE_PATH}"
            file_check_res = requests.get(file_check_url, headers=HEADERS_GITHUB, params={"ref": default_branch})

            if file_check_res.status_code == 200:
                repos_with_check.append(full_name)
                continue

            # Step 4: Create branch
            sha = get_latest_commit_sha(full_name, default_branch)
            if not sha:
                print(f"⚠️ Failed to get commit SHA for {full_name}")
                continue

            create_branch(full_name, BRANCH_NAME, sha)

            # Step 5: Upload file
            success = upload_file_to_repo(
                org=ORG,
                repo=name,
                path=FILE_PATH,
                content=validate_pr_title_yml,
                message=PR_TITLE,
                branch=BRANCH_NAME
            )
            if not success:
                repos_missing_check.append(full_name)
                continue

            # Step 6: Create PR
            pr = create_pr(full_name, BRANCH_NAME, default_branch)
            if pr and "html_url" in pr:
                prs_created.append(f"<{pr['html_url']}|{full_name}>")
            else:
                repos_missing_check.append(full_name)

    # Final Slack Message
    msg = f"*Command Ran:* `/enforce-pr-title-check` by <@{user_id}>\n\n"
    msg += f"✅ Repos with existing check: `{len(repos_with_check)}`\n"
    if repos_with_check:
        msg += "\n".join([f"• {r}" for r in repos_with_check[:10]])
        if len(repos_with_check) > 10:
            msg += "\n..."

    msg += f"\n\n🛠️ PRs created to add check: `{len(prs_created)}`\n"
    if prs_created:
        msg += "\n".join([f"• {r}" for r in prs_created])

    if repos_missing_check:
        msg += f"\n\n❌ Failed to update `{len(repos_missing_check)}` repos:\n"
        msg += "\n".join([f"• {r}" for r in repos_missing_check[:10]])
        if len(repos_missing_check) > 10:
            msg += "\n..."

    post_to_slack(response_url, msg.strip())

# ---- WORKFLOW 11 enforce_branch_rules----

def enforce_branch_rules(response_url, user_id):
    ORG = "LearningMotors"
    BRANCH_NAME = "add-go-checks"
    FILE_PATH = ".github/workflows/go-checks.yml"
    PR_TITLE = "Add Go Checks via Reusable Workflow"
    PR_BODY = "This PR sets up centralized branch source validation via a reusable GitHub Actions workflow."

    # ✅ Use centralized reusable workflow
    go_checks_yml = """
name: Go Checks

on:
  pull_request:
    branches:
      - main
      - develop

permissions:
  contents: read

jobs:
  go-checks:
    name: Go Checks
    uses: LearningMotors/backend-workflows/.github/workflows/go-checks.yml@main
"""

    repos_with_check = []
    repos_missing_check = []
    prs_created = []

    # Step 1: List all repos in the org
    repos = []
    for page in range(1, 6):  # Adjust to max pages needed
        url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page={page}"
        res = requests.get(url, headers=HEADERS_GITHUB)
        if res.status_code == 200:
            page_repos = res.json()
            if not page_repos:
                break
            repos.extend(page_repos)
        else:
            print(f"❌ Failed to fetch repos on page {page}")
            break


    for repo in repos:
        name = repo["name"]
        full_name = repo["full_name"]

        # Step 2: Filter by topics
        topic_url = f"https://api.github.com/repos/{full_name}/topics"
        topic_res = requests.get(topic_url, headers={**HEADERS_GITHUB, "Accept": "application/vnd.github.mercy-preview+json"})
        topics = topic_res.json().get("names", []) if topic_res.status_code == 200 else []

        print(f"🔍 {full_name} has topics: {topics}")

        if "production-true" in topics and "team-backend" in topics:
            # Step 3: Check if file already exists
            default_branch = get_default_branch(full_name)
            file_check_url = f"https://api.github.com/repos/{full_name}/contents/{FILE_PATH}"
            file_check_res = requests.get(file_check_url, headers=HEADERS_GITHUB, params={"ref": default_branch})

            if file_check_res.status_code == 200:
                repos_with_check.append(full_name)
                continue

            # Step 4: Create branch from latest commit SHA
            sha = get_latest_commit_sha(full_name, default_branch)
            if not sha:
                print(f"⚠️ Failed to get commit SHA for {full_name}")
                continue

            #create_branch(full_name, BRANCH_NAME, sha)

            created = create_branch(full_name, BRANCH_NAME, sha)
            if not created:
                print(f"❌ Could not create branch in {full_name}")
                repos_missing_check.append(full_name)
                continue


            # Step 5: Upload workflow file
            success = upload_file_to_repo(
                org=ORG,
                repo=name,
                path=FILE_PATH,
                content=go_checks_yml,
                message=PR_TITLE,
                branch=BRANCH_NAME
            )
            if not success:
                repos_missing_check.append(full_name)
                continue

            # Step 6: Create PR
            pr = create_pr(full_name, BRANCH_NAME, default_branch)
            if pr and "html_url" in pr:
                prs_created.append(f"<{pr['html_url']}|{full_name}>")
            else:
                repos_missing_check.append(full_name)

    # ✅ Final Slack message
    msg = f"*Command Ran:* `/enforce-branch-rules` by <@{user_id}>\n\n"
    msg += f"✅ Repos with existing check: `{len(repos_with_check)}`\n"
    if repos_with_check:
        msg += "\n".join([f"• {r}" for r in repos_with_check[:10]])
        if len(repos_with_check) > 10:
            msg += "\n..."

    msg += f"\n\n🛠️ PRs created to add check: `{len(prs_created)}`\n"
    if prs_created:
        msg += "\n".join([f"• {r}" for r in prs_created])

    if repos_missing_check:
        msg += f"\n\n❌ Failed to update `{len(repos_missing_check)}` repos:\n"
        msg += "\n".join([f"• {r}" for r in repos_missing_check[:10]])
        if len(repos_missing_check) > 10:
            msg += "\n..."

    post_to_slack(response_url, msg.strip())




# ---WORKFLOW 12 REPO SETTINGS ---

def handle_repo_settings_audit(response_url, user_id):
    post_to_slack(response_url, f"🧪 Received `/repo-settings audit` from <@{user_id}>. Starting audit...")

    ORG = "LearningMotors"
    compliant = []
    noncompliant = []

    # Manually test only Automatic-Creatt repo
    repos = [{
        "full_name": "LearningMotors/Automatic-Creatt",
        "name": "Automatic-Creatt"
    }]

    for repo in repos:
        try:
            full_name = repo["full_name"]
            repo_name = repo["name"]
            problems = []

            # Workflow files
            workflows = ["validate_pr_title.yml", "go-checks.yml", "codecov.yml", "DependencyReview.yml"]
            for wf in workflows:
                wf_url = f"https://api.github.com/repos/{full_name}/contents/.github/workflows/{wf}"
                r = requests.get(wf_url, headers=HEADERS_GITHUB, timeout=10)
                if r.status_code == 200:
                    problems.append(f"Has {wf}")
                else:
                    problems.append(f"Missing {wf}")

            # CODEOWNERS
            r = requests.get(f"https://api.github.com/repos/{full_name}/contents/CODEOWNERS", headers=HEADERS_GITHUB, timeout=10)
            if r.status_code == 200:
                problems.append("Has CODEOWNERS")
            else:
                problems.append("Missing CODEOWNERS file")

            # Team permissions
            team_url = f"https://api.github.com/orgs/{ORG}/teams/india-backend/repos/{full_name}"
            r = requests.get(team_url, headers=HEADERS_GITHUB, timeout=10)
            if r.status_code == 204:
                problems.append("✅ india-backend team has access")
            elif r.ok:
                permissions = r.json().get("permissions", {})
                if permissions.get("push", False):
                    problems.append("✅ india-backend team has write access")
                else:
                    problems.append("⚠️ india-backend team does not have write access")
            else:
                problems.append("⚠️ Error checking team permissions")

            # Branch protection
            branches_url = f"https://api.github.com/repos/{full_name}/branches"
            branches_res = requests.get(branches_url, headers=HEADERS_GITHUB, timeout=10)
            branch_names = [b.get("name") for b in branches_res.json()] if branches_res.ok else []

            relevant_branches = [b for b in branch_names if b in ["main", "master", "develop"] or b.startswith("release_")]

            for branch in relevant_branches:
                bp_url = f"https://api.github.com/repos/{full_name}/branches/{branch}/protection"
                bp_res = requests.get(bp_url, headers=HEADERS_GITHUB, timeout=10)
                print(f"🔍 Checking branch protections for {repo_name}/{branch} → {bp_res.status_code}")

                if not bp_res.ok:
                    problems.append(f"No branch protection on `{branch}`")
                    continue

                data = bp_res.json()

                pr_reviews = data.get("required_pull_request_reviews", {})
                if not pr_reviews:
                    problems.append(f"`{branch}`: PR review not required")
                else:
                    if pr_reviews.get("required_approving_review_count", 0) < 1:
                        problems.append(f"`{branch}`: <1 required approval")
                    else:
                        problems.append(f"`{branch}`: ✅ Requires {pr_reviews['required_approving_review_count']} approval(s)")
                    if pr_reviews.get("dismiss_stale_reviews"):
                        problems.append(f"`{branch}`: ✅ Dismisses stale reviews")
                    else:
                        problems.append(f"`{branch}`: stale approvals not dismissed")

                status_checks = data.get("required_status_checks", {})
                contexts = status_checks.get("contexts", [])
                if not contexts:
                    problems.append(f"`{branch}`: no required status checks selected")
                else:
                    problems.append(f"`{branch}`: ✅ Required checks – {', '.join(contexts)}")

                if data.get("required_conversation_resolution", {}).get("enabled", False):
                    problems.append(f"`{branch}`: ✅ Conversation resolution enabled")
                else:
                    problems.append(f"`{branch}`: conversation resolution not enforced")

            if not [p for p in problems if "❌" in p or "Missing" in p or "⚠️" in p or "not enforced" in p or "not dismissed" in p or "<1" in p]:
                compliant.append(repo_name)
            else:
                noncompliant.append(f"{repo_name} – " + "; ".join(problems))

        except Exception as e:
            print(f"🔥 Exception in auditing {repo.get('full_name', 'unknown')}: {e}")
            noncompliant.append(f"{repo.get('name', 'unknown')} – Unexpected error during audit")

    # Format Slack output
    msg_lines = [
        f"📊 *Repo Settings Audit Report* by <@{user_id}>:",
        f"✅ *Compliant Repos:* `{len(compliant)}`",
        f"❌ *Noncompliant Repos:* `{len(noncompliant)}`",
        "–––––––––––––––––––––––––"
    ]

    for name in compliant:
        msg_lines.append(f"✅ <https://github.com/{ORG}/{name}|{name}> – All checks passed")

    for entry in noncompliant:
        try:
            repo_name, issues_str = entry.split(" – ", 1)
            repo_link = f"<https://github.com/{ORG}/{repo_name}|{repo_name}>"
            msg_lines.append(f"❌ {repo_link}")

            issues = [i.strip() for i in issues_str.split(";")]
            general_issues = []
            branch_protection_issues = []

            for issue in issues:
                if issue.startswith("Missing"):
                    general_issues.append(f"• ❌ {issue}")
                elif issue.startswith("Has"):
                    general_issues.append(f"• ✅ {issue.replace('Has', '').strip()}")
                elif issue.startswith("✅ india-backend") or issue.startswith("⚠️ india-backend"):
                    general_issues.append(f"• {issue}")
                elif issue.startswith("No branch protection") or issue.startswith("`"):
                    branch_protection_issues.append(issue)
                else:
                    general_issues.append(f"• ⚠️ {issue}")

            msg_lines.extend(general_issues)

            if branch_protection_issues:
                msg_lines.append("🔐 *Branch Protection Checks:*")
                for bp_issue in branch_protection_issues:
                    if "✅" in bp_issue:
                        msg_lines.append(f"• ✅ {bp_issue.replace('`', '')}")
                    elif "not" in bp_issue or "<1" in bp_issue:
                        msg_lines.append(f"• ❌ {bp_issue.replace('`', '')}")
                    else:
                        msg_lines.append(f"• ⚠️ {bp_issue.replace('`', '')}")

        except:
            msg_lines.append(f"❌ {entry}")

    post_to_slack(response_url, "\n".join(msg_lines).strip())





def handle_repo_settings_enforce(response_url, user_id):
    post_to_slack(response_url, f":gear: Received `/repo-settings enforce` from <@{user_id}>. Starting enforcement...")

    ORG = "LearningMotors"
    REPO = "Automatic-Creatt"
    FULL_NAME = f"{ORG}/{REPO}"
    BRANCH = "main"

    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(FULL_NAME)

    messages = [f"🔐 *Repo Settings Enforcement Report* for <@{user_id}>", f"Target: <https://github.com/{FULL_NAME}|{FULL_NAME}>", "–––––––––––––––––––––––––––"]

    # 1. Enforce workflow files
    workflows = {
        "validate_pr_title.yml": '''name: Validate PR Title

on:
  pull_request:
    types: [opened, edited, synchronize]

permissions:
  contents: read

jobs:
  check-title:
    runs-on: ubuntu-latest
    steps:
      - name: Check PR title format
        run: |
          TITLE="${{ github.event.pull_request.title }}"
          echo "PR Title: $TITLE"

          if [[ ! "$TITLE" =~ ^[A-Z]+-[0-9]+\\ -\\ .+$ ]]; then
            echo "❌ PR title must match the format: [A-Z]+-[0-9]+ - <Description>"
            echo "✅ Example: SRE-21 - Enforce Jira IDs in commit messages on GitHub"
            exit 1
          else
            echo "✅ PR title format is valid!"
          fi
        shell: bash''',

        "go-checks.yml": '''name: Go Checks

on:
  pull_request:
    branches:
      - develop

jobs:
  go-checks:
    name: Go Checks
    uses: LearningMotors/backend-workflows/.github/workflows/go-checks.yml@main''',

        "codecov.yml": '''name: Codecov
permissions:
  contents: read
  pull-requests: read

on:
  push:
    branches:
      - main
      - master
      - develop
  pull_request:
    branches:
      - main
      - master
      - develop

jobs:
  build:
    runs-on: ubuntu-latest

    steps:      
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Configure Git and Authenticate with private dependencies
        run: |
          mkdir -p ~/.ssh
          echo "$SSH_KEY" >> ~/.ssh/id_rsa &&
          chmod 400 ~/.ssh/id_rsa &&
          git config --global url."git@github.com:LearningMotors/".insteadOf "https://github.com/LearningMotors/" &&
          ssh-keyscan -H github.com >> ~/.ssh/known_hosts
          sudo apt-get update &&
          sudo apt-get install -y pkg-config libopus-dev libopusfile-dev libasound-dev portaudio19-dev
        env:
          SSH_KEY: ${{ secrets.SSH_KEY }}

      - name: Set GO_PRIVATE
        run: go env -w GOPRIVATE=github.com/LearningMotors/*

      - name: Run Tests and coverage
        run: |
          go test ./... -coverprofile=coverage.out -covermode=atomic
          ssh-keyscan -H github.com >> ~/.ssh/known_hosts &&
          sudo apt-get update &&
          sudo apt-get install -y pkg-config libopus-dev libopusfile-dev
          
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v5.0.7
        env: 
            CODECOV_TOKEN: ${{ secrets.CODECOV_TOKEN }}''',

        "DependencyReview.yml": '''name: DependencyReview

on:
  pull_request:
    branches:
      - main
      - master
      - develop

permissions:
  contents: read
  pull-requests: write

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - name: 'Checkout Repository'
        uses: actions/checkout@v4

      - name: 'Dependency Review'
        id: dependency_review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: low
          comment-summary-in-pr: always
          license-check: false'''
    }

    pr_branch = f"enforce-repo-settings-{int(time.time())}"
    repo.create_git_ref(ref=f"refs/heads/{pr_branch}", sha=repo.get_branch(BRANCH).commit.sha)

    pr_files_added = []

    for filename, content in workflows.items():
        path = f".github/workflows/{filename}"
        try:
            repo.get_contents(path, ref=BRANCH)
            messages.append(f":white_check_mark: `{filename}` already exists")
        except:
            repo.create_file(path, f"Add {filename}", content, branch=pr_branch)
            pr_files_added.append(path)
            messages.append(f":sparkles: Added `{filename}`")

    # 2. CODEOWNERS
    codeowners_path = "CODEOWNERS"
    codeowners_content = '''# No CODEOWNERS defined yet'''

    try:
        repo.get_contents(codeowners_path, ref=BRANCH)
        messages.append(":white_check_mark: `CODEOWNERS` already exists")
    except:
        repo.create_file(codeowners_path, "Add CODEOWNERS file", codeowners_content, branch=pr_branch)
        pr_files_added.append(codeowners_path)
        messages.append(":sparkles: Added `CODEOWNERS`")

    # 3. Team Permission Check (india-backend)
    # 3. Team Permission Check (india-backend)
    try:
        org = g.get_organization(ORG)
        team = org.get_team_by_slug("india-backend")
        
        team_repos = [r.name for r in team.get_repos()]
        if REPO in team_repos:
            messages.append(":white_check_mark: `india-backend` team already has access")
        else:
            team.add_to_repos(repo)
            team.set_repo_permission(repo, "push")
            messages.append(":sparkles: Granted `write` access to `india-backend` team")
            
    except Exception as e:
        messages.append(f":warning: Failed to verify or apply team permissions: `{e}`")


    # 3. Branch Protection
    try:
        branch = repo.get_branch(BRANCH)
        protection = branch.get_protection()

        pr_reviews = protection.required_pull_request_reviews
        status_checks = protection.required_status_checks
        conversation = protection.required_conversation_resolution

        protection_ok = (
            pr_reviews and pr_reviews.dismiss_stale_reviews and
            pr_reviews.required_approving_review_count >= 1 and
            status_checks and status_checks.contexts and
            conversation and conversation.enabled
        )

        if protection_ok:
            messages.append(f":white_check_mark: Branch protection on `{BRANCH}` already configured")
        else:
            raise Exception("Partial config")

    except:
        try:
            protection_url = f"https://api.github.com/repos/{FULL_NAME}/branches/{BRANCH}/protection"
            headers = {
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github.luke-cage-preview+json"
            }
            protection_payload = {
                "required_status_checks": {
                    "strict": False,
                    "contexts": [
                        "Go Checks",
                        "Codecov",
                        "Dependency Review",
                        "Validate PR Title"
                    ]
                },
                 "enforce_admins": True,
                 "required_pull_request_reviews": {
                     "dismiss_stale_reviews": True,
                     "require_code_owner_reviews": False,
                     "required_approving_review_count": 1
                },
                "restrictions": None,
                "required_conversation_resolution": True,
                "bypass_pull_request_allowances": {}  # ✅ This works with raw API
            }
            res = requests.put(protection_url, headers=headers, json=protection_payload)
            if res.status_code == 200:
                messages.append(f":lock: Applied branch protection on `{BRANCH}`")
            else:
                messages.append(f":x: Failed to apply branch protection: `{res.status_code} {res.text}`")

            branch.edit_required_status_checks(
                strict=False,
                contexts=[
                    "Go Checks",
                    "Codecov",
                    "Dependency Review",
                    "Validate PR Title"
                ]
            )

            #branch.require_conversation_resolution()

            #messages.append(f":lock: Applied branch protection on `{BRANCH}`")
            #messages.append(f":lock: Applied branch protection on `{BRANCH}`")
            #messages.append(f"• ✅ Required PR reviews (1 approval)")
            #messages.append(f"• ✅ Dismiss stale reviews")
            #messages.append(f"• ✅ Require conversation resolution")
            #messages.append(f"• ✅ Status checks: Go Checks, Codecov, Dependency Review, Validate PR Title")


        except Exception as e:
            messages.append(f":x: Failed to apply branch protection: `{e}`")

    # 4. Create PR if needed
    if pr_files_added:
        pr = repo.create_pull(
            title="Enforce Repo Settings",
            body="This PR adds required workflow files and CODEOWNERS.",
            head=pr_branch,
            base=BRANCH
        )
        messages.append(f":rocket: Created PR to add missing files: <{pr.html_url}|View PR>")

    post_to_slack(response_url, "\n".join(messages))



# --- Helper: Flag Extractor ---
def extract_flag(flags, name):
    if name not in flags:
        return None
    try:
        value = flags.split(name)[1].strip().split()[0]
        return value
    except:
        return None


# --- GITHUB HELPERS ---
def branch_exists(repo, branch):
    url = f"https://api.github.com/repos/{repo}/branches/{branch}" 
    print(f"📦 Checking branch URL: {url}")
    res = requests.get(url, headers=HEADERS_GITHUB)
    print(f"🔁 Status code: {res.status_code}, Response: {res.text}")
    return res.status_code == 200

def get_latest_commit_sha(repo, branch):
    url = f"https://api.github.com/repos/{repo}/git/refs/heads/{branch}"
    res = requests.get(url, headers=HEADERS_GITHUB)
    if res.status_code == 200:
        return res.json()["object"]["sha"]
    return None

def create_branch(repo, new_branch, sha):
    url = f"https://api.github.com/repos/{repo}/git/refs"
    payload = {"ref": f"refs/heads/{new_branch}", "sha": sha}
    res = requests.post(url, headers=HEADERS_GITHUB, json=payload)
    return res.status_code in [201, 200]


def find_existing_pr(repo, head, base, include_closed=False):
    url = f"https://api.github.com/repos/{repo}/pulls"
    params = {
        "head": f"{GITHUB_USER}:{head}",
        "base": base,
        "state": "all" if include_closed else "open"
    }
    res = requests.get(url, headers=HEADERS_GITHUB, params=params)
    if res.status_code == 200 and res.json():
        return res.json()[0]
    return None
def check_mergeability(pr_url):
    for _ in range(3):
        pr_details = requests.get(pr_url, headers=HEADERS_GITHUB).json()
        mergeable = pr_details.get("mergeable")
        if mergeable is not None:
            return mergeable
        time.sleep(2)
    return False


def create_pr(repo, head, base):
    repo_name = repo.split("/")[-1]
    if head.startswith("add-pr-title-check"):
        title = f"SRE-000 - Add PR Title Check to {repo_name}"
    else:
        title = f"{head} → {base}"

    url = f"https://api.github.com/repos/{repo}/pulls"
    res = requests.post(url, headers=HEADERS_GITHUB, json={
        "title": title,
        "head": head,
        "base": base,
        "body": "Slack workflow auto-created PR"
    })

    if res.status_code in [200, 201]:
        return res.json()

    # Fallback: if PR exists but is closed
    if res.status_code == 422:
        print(f"⚠️ GitHub 422 response: {res.text}")
        # Try fetching any PR (open or closed)
        fallback = find_existing_pr(repo, head, base, include_closed=True)
        if fallback:
            return fallback

    print(f"❌ Failed to create PR for {repo}: {res.status_code} – {res.text}")
    return None
    
def check_pr_status(repo, sha):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs"
    res = requests.get(url, headers=HEADERS_GITHUB)

    if res.status_code != 200:
        return False, {"error": f"Failed to fetch check runs ({res.status_code})"}

    runs = res.json().get("check_runs", [])
    if not runs:
        return False, {"warning": "No CI checks found for this commit"}

    failed = [run for run in runs if run["conclusion"] != "success"]
    if failed:
        return False, {"failed": failed}

    return True, {"passed": runs}

def is_release_branch_behind(repo, base, head):
    url = f"https://api.github.com/repos/{repo}/compare/{base}...{head}"
    res = requests.get(url, headers=HEADERS_GITHUB)
    if res.status_code != 200:
        print(f"⚠️ Compare API failed for {repo}: {res.status_code} – {res.text}")
        return None
    data = res.json()
    return data.get("status") == "behind"

def has_commits_between(repo, base, head):
    url = f"https://api.github.com/repos/{repo}/compare/{base}...{head}"
    res = requests.get(url, headers=HEADERS_GITHUB)
    if res.status_code == 200:
        data = res.json()
        return data.get("total_commits", 0) > 0
    return False


def approve_pr(repo, pr_url):
    if not pr_url:
        return False

    pr_id = pr_url.split("/")[-1]
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_id}/reviews"
    res = requests.post(url, headers=HEADERS_GITHUB, json={"event": "APPROVE"})

    if res.status_code in [200, 201]:
        print(f"✅ Approved PR #{pr_id} in {repo}")
        return True
    else:
        print(f"❌ Failed to approve PR #{pr_id} in {repo}: {res.status_code} – {res.text}")
        return False



def get_jira_version_id(version_name):
    url = f"{JIRA_BASE_URL}/rest/api/3/project/{JIRA_PROJECT_KEY}/versions"
    res = requests.get(url, headers=JIRA_HEADERS)
    if res.status_code != 200:
        print(f"⚠️ Failed to fetch versions: {res.status_code}")
        return None
    for v in res.json():
        if v["name"] == version_name:
            return v["id"]
    return None

def get_file_content(repo, path, branch):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    res = requests.get(url, headers=HEADERS_GITHUB, params={"ref": branch})
    if res.status_code != 200:
        print(f"⚠️ Failed to fetch file {path} from {repo}: {res.status_code}")
        return None
    data = res.json()
    content = b64decode(data["content"]).decode() if data.get("encoding") == "base64" else data["content"]
    return {"decoded": content, "sha": data["sha"]}


import re

def update_image_patch_yaml(original_content, service_name, branch_name, short_sha):
    """
    Updates only the SHA part of the image tag in image-patch.yaml.
    For example: gcr.io/suki-build/ms-jobber:main.abc1234 → gcr.io/suki-build/ms-jobber:main.23057cb
    """
    pattern = rf"(gcr\.io/suki-build/{service_name}:{branch_name})\.[a-f0-9]{{7,40}}"
    replacement = rf"\1.{short_sha}"

    # 🧪 Debug prints
    print("🧪 Pattern being used:", pattern)
    print("🧪 Replacement string:", replacement)
    print("🧪 Searching in YAML content:\n", original_content)

    updated_content, count = re.subn(pattern, replacement, original_content)

    if count == 0:
        print(f"⚠️ No match found for service={service_name}, branch={branch_name} in image-patch.yaml.")
        return None

    return updated_content




def commit_file_change(repo, path, new_content, message, branch, sha):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    content_b64 = b64encode(new_content.encode()).decode()
    payload = {
        "message": message,
        "content": content_b64,
        "branch": branch,
        "sha": sha
    }
    res = requests.put(url, headers=HEADERS_GITHUB, json=payload)
    return res.status_code in [200, 201]


def open_pr_in_manifest(repo, branch, service, sha, release_version, pr_title_override=None):
    title = pr_title_override or f"Prod deploy: {release_version} for {service}"
    body = f"Updates image tag for `{service}` to `{sha}` in prod."
    url = f"https://api.github.com/repos/{repo}/pulls"
    payload = {
        "title": title,
        "head": branch,
        "base": "main",
        "body": body
    }
    res = requests.post(url, headers=HEADERS_GITHUB, json=payload)
    if res.status_code in [200, 201]:
        return res.json()["html_url"]
    print(f"Failed to open PR: {res.status_code} {res.text}")
    return None

def get_default_branch(repo):
    url = f"https://api.github.com/repos/{repo}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("default_branch", "main")
    else:
        return "main"



def has_permission(command, user_id):
    allowed = COMMAND_PERMISSIONS.get(command, [])
    return user_id in allowed

def get_main_or_master_branch(repo):
    """
    Checks if the given GitHub repo has a 'main' or 'master' branch.
    Returns the branch name if found.
    Raises an Exception if neither branch exists.
    """
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    for branch in ["main", "master"]:
        url = f"https://api.github.com/repos/{repo}/branches/{branch}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return branch

    raise Exception(f"❌ Neither 'main' nor 'master' branch found in repo: {repo}")

def get_main_or_master_branch_strict(repo):
    for branch in ["main", "master"]:
        url = f"https://api.github.com/repos/{repo}/branches/{branch}"
        res = requests.get(url, headers=HEADERS_GITHUB)
        
        # Only accept if GitHub confirms the branch name exactly (no redirect)
        if res.status_code == 200:
            data = res.json()
            actual_branch = data.get("name", "")
            if actual_branch == branch:
                print(f"✅ Confirmed real branch '{branch}' for {repo}")
                return branch
            else:
                print(f"⚠️ {repo} -> '{branch}' resolved to different branch: {actual_branch}")
    
    return None
