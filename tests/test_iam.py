# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import httpx
import pytest

from helper_scripts import ge_egress, iam

ALICE = "principal://agents/alice"
BOB = "principal://agents/bob"


def test_missing_members_none_when_all_bound():
    policy = {"bindings": [{"role": "roles/iap.viewer", "members": [ALICE, BOB]}]}
    assert iam.missing_members(policy, {"roles/iap.viewer": {ALICE}}) == {}


def test_missing_members_reports_new_role_and_members():
    policy = {"bindings": [{"role": "roles/iap.viewer", "members": [ALICE]}]}
    missing = iam.missing_members(policy, {"roles/iap.viewer": {ALICE, BOB}, "roles/iap.egressor": {ALICE}})
    assert missing == {"roles/iap.viewer": {BOB}, "roles/iap.egressor": {ALICE}}


def test_conditional_bindings_do_not_count():
    policy = {"bindings": [{"role": "roles/iap.viewer", "members": [ALICE], "condition": {"expression": "x"}}]}
    assert iam.missing_members(policy, {"roles/iap.viewer": {ALICE}}) == {"roles/iap.viewer": {ALICE}}


def test_add_members_preserves_others_and_conditions():
    conditional = {"role": "roles/iap.viewer", "members": ["user:c"], "condition": {"expression": "x"}}
    policy = {"etag": "abc", "bindings": [conditional, {"role": "roles/owner", "members": ["user:o"]}]}
    iam.add_members(policy, {"roles/iap.viewer": {ALICE}})

    assert policy["etag"] == "abc"
    assert conditional["members"] == ["user:c"]
    assert {"role": "roles/owner", "members": ["user:o"]} in policy["bindings"]
    assert {"role": "roles/iap.viewer", "members": [ALICE]} in policy["bindings"]


def card(project, agent_id):
    url = f"https://x/v1/a2a/projects/{project}/locations/global/dataAgents/{agent_id}"
    return {"a2aAgentDefinition": {"jsonAgentCard": json.dumps({"url": url})}}


PROJECTS = {"my-proj", "123"}


def test_matches_agent_by_exact_card_url():
    agent_ids = {"my_agent"}
    assert iam.matches_agent(card("my-proj", "my_agent"), agent_ids, PROJECTS)
    assert iam.matches_agent(card("123", "my_agent"), agent_ids, PROJECTS)  # project number
    # Same prefix, other project, or other agent: no match.
    assert not iam.matches_agent(card("my-proj", "my_agent_v2"), agent_ids, PROJECTS)
    assert not iam.matches_agent(card("my-proj", "my_agent-eu"), agent_ids, PROJECTS)
    assert not iam.matches_agent(card("other-proj", "my_agent"), agent_ids, PROJECTS)


def test_card_takes_precedence_over_display_name():
    ge_agent = {"displayName": "my_agent", **card("my-proj", "other_agent")}
    assert not iam.matches_agent(ge_agent, {"my_agent"}, PROJECTS)


def test_matches_agent_by_exact_display_name_without_card():
    agent_ids = {"my_agent"}
    assert iam.matches_agent({"displayName": "my_agent"}, agent_ids, PROJECTS)
    assert iam.matches_agent({"displayName": "my_agent [BQCA Agent]"}, agent_ids, PROJECTS)
    assert not iam.matches_agent({"displayName": "my_agent_v2"}, agent_ids, PROJECTS)
    assert not iam.matches_agent({"displayName": "my_agent team bot"}, agent_ids, PROJECTS)


def mock_client(policy, set_calls, get_calls=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(":getIamPolicy"):
            if get_calls is not None:
                get_calls.append(json.loads(request.content))
            return httpx.Response(200, json=policy)
        if request.url.path.endswith(":setIamPolicy"):
            set_calls.append(json.loads(request.content))
            return httpx.Response(200, json={})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ensure_bindings_noop_when_present():
    set_calls = []
    client = mock_client({"bindings": [{"role": "roles/iap.viewer", "members": [ALICE]}]}, set_calls)
    assert iam.ensure_bindings(client, "https://x/projects/p", {"roles/iap.viewer": {ALICE}}) == {}
    assert set_calls == []


def test_ensure_bindings_dry_run_does_not_set():
    set_calls = []
    client = mock_client({"bindings": []}, set_calls)
    missing = iam.ensure_bindings(client, "https://x/projects/p", {"roles/iap.viewer": {ALICE}}, dry_run=True)
    assert missing == {"roles/iap.viewer": {ALICE}}
    assert set_calls == []


def test_ensure_bindings_sets_when_missing_using_policy_version_3():
    set_calls, get_calls = [], []
    client = mock_client({"etag": "e1", "bindings": []}, set_calls, get_calls)
    iam.ensure_bindings(client, "https://x/projects/p", {"roles/iap.viewer": {ALICE}})
    assert get_calls == [{"options": {"requestedPolicyVersion": 3}}]
    assert set_calls == [{"policy": {
        "etag": "e1", "version": 3, "bindings": [{"role": "roles/iap.viewer", "members": [ALICE]}],
    }}]


def test_discover_principals_follows_pagination():
    def handler(request: httpx.Request) -> httpx.Response:
        page2 = request.url.params.get("pageToken") == "p2"
        if request.url.path.endswith("/engines"):
            if page2:
                return httpx.Response(200, json={"engines": [{"name": "projects/123/engines/e2"}]})
            return httpx.Response(200, json={"engines": [{"name": "projects/123/engines/e1"}], "nextPageToken": "p2"})
        if "/engines/e2/" in request.url.path and page2:
            return httpx.Response(200, json={"agents": [{
                **card("my-proj", "my_agent"), "agentIdentityInfo": {"spiffeId": "//agents/a"},
            }]})
        if "/engines/e2/" in request.url.path:
            return httpx.Response(200, json={"agents": [], "nextPageToken": "p2"})
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert iam.discover_principals(client, "my-proj", "123", {"my_agent"}) == {"principal://agents/a"}


def test_discover_principals_scopes_to_app_ids():
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if "/engines/app-2/" in request.url.path:
            return httpx.Response(200, json={"agents": [{
                **card("my-proj", "my_agent"), "agentIdentityInfo": {"spiffeId": "//agents/b"},
            }]})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert iam.discover_principals(client, "my-proj", "123", {"my_agent"}, app_ids={"app-2"}) == {
        "principal://agents/b"
    }
    assert paths == [
        "/v1alpha/projects/123/locations/global/collections/default_collection/engines/app-2/assistants/default_assistant/agents"
    ]


def test_parse_args_accepts_app_id():
    args = ge_egress.parse_args(["--project_id=p", "--app_id", "app-1", "app-2"])
    assert args.app_id == ["app-1", "app-2"]


def test_parse_args_help_mentions_helper_scripts_module(capsys):
    with pytest.raises(SystemExit) as exc:
        ge_egress.parse_args(["--help"])
    assert exc.value.code == 0
    assert "python -m helper_scripts.ge_egress" in capsys.readouterr().out


def test_ensure_bindings_raises_on_set_iam_policy_error(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(":getIamPolicy"):
            return httpx.Response(200, json={"bindings": []})
        if request.url.path.endswith(":setIamPolicy"):
            return httpx.Response(403, text="denied")
        return httpx.Response(404)

    client = mock_http(handler)
    with pytest.raises(RuntimeError, match=r"setIamPolicy failed \(403\)"):
        iam.ensure_bindings(client, "https://x/projects/p", {"roles/iap.viewer": {ALICE}})


def test_configure_egress_binds_project_and_iap_web_roles(mock_http):
    set_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/projects/my-proj":
            return httpx.Response(200, json={"projectNumber": "123"})
        if "/engines/app-2/" in path:
            return httpx.Response(200, json={"agents": [{
                **card("my-proj", "my_agent"), "agentIdentityInfo": {"spiffeId": "//agents/a"},
            }]})
        if path.endswith(":getIamPolicy"):
            return httpx.Response(200, json={"etag": "e1", "bindings": []})
        if path.endswith(":setIamPolicy"):
            set_calls.append((request.url.host + path, json.loads(request.content)["policy"]["bindings"]))
            return httpx.Response(200, json={})
        return httpx.Response(404)

    client = mock_http(handler)
    iam.configure_egress(client, "my-proj", {"my_agent"}, app_ids={"app-2"})
    assert set_calls == [
        (
            "cloudresourcemanager.googleapis.com/v1/projects/my-proj:setIamPolicy",
            [
                {"role": "roles/iap.viewer", "members": ["principal://agents/a"]},
                {"role": "roles/iap.egressor", "members": ["principal://agents/a"]},
            ],
        ),
        (
            "iap.googleapis.com/v1/projects/123/iap_web:setIamPolicy",
            [{"role": "roles/iap.egressor", "members": ["principal://agents/a"]}],
        ),
    ]


def test_configure_egress_noop_without_matching_principals(mock_http):
    seen_paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if request.url.path == "/v1/projects/my-proj":
            return httpx.Response(200, json={"projectNumber": "123"})
        if "/engines/app-2/" in request.url.path:
            return httpx.Response(200, json={"agents": []})
        return httpx.Response(404)

    client = mock_http(handler)
    iam.configure_egress(client, "my-proj", {"my_agent"}, app_ids={"app-2"})
    assert not any(p.endswith((":getIamPolicy", ":setIamPolicy")) for p in seen_paths)


def test_main_normalizes_app_ids_and_passes_flags(monkeypatch):
    captured = {}
    monkeypatch.setattr(ge_egress, "get_credentials", lambda: object())
    monkeypatch.setattr(ge_egress, "auth_headers", lambda creds, project_id: {})

    def fake_configure_egress(http, project_id, agent_ids, dry_run=False, app_ids=None):
        captured.update(
            project_id=project_id, agent_ids=agent_ids, dry_run=dry_run, app_ids=app_ids
        )

    monkeypatch.setattr(ge_egress.iam, "configure_egress", fake_configure_egress)
    ge_egress.main([
        "--project_id=my-proj",
        "--app_id",
        " projects/123/locations/global/collections/default_collection/engines/app-1/ ",
        "app-2",
        "--agent_ids",
        "agent_a",
        "--dry-run",
    ])
    assert captured == {
        "project_id": "my-proj",
        "agent_ids": {"agent_a"},
        "dry_run": True,
        "app_ids": {"app-1", "app-2"},
    }


def test_main_rejects_empty_app_id(capsys):
    with pytest.raises(SystemExit) as exc:
        ge_egress.main(["--project_id=my-proj", "--app_id", " ", "/"])
    assert exc.value.code == 2
    assert "--app_id requires at least one non-empty app ID." in capsys.readouterr().err
