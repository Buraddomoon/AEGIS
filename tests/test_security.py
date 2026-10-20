import uuid

import pytest
from aegis.db import session_factory
from aegis.models import AuditEvent, Laboratory
from aegis.reporting import HTMLReportExporter, build_report
from conftest import create_queued
from sqlalchemy import select


def test_unauthenticated_and_csrf_denied(client):
    assert client.get('/api/v1/coverage').status_code == 401
    payload = {"username": "viewer", "password": "Test-only-randomized-scope-23!"}
    assert client.post('/api/v1/auth/login', json=payload).status_code == 403
    login = client.post('/api/v1/auth/login', json=payload, headers={"x-aegis-request": "browser"})
    assert login.status_code == 200
    assert 'HttpOnly' in login.headers.get_list('set-cookie')[0]
    assert 'SameSite=strict' in login.headers.get_list('set-cookie')[0]
    assert client.post('/api/v1/auth/logout').status_code == 403
    assert client.post('/api/v1/auth/logout', headers={"x-csrf-token": "wrong"}).status_code == 403
    assert client.post('/api/v1/auth/logout', headers={"x-csrf-token": login.json()['csrf_token']}).status_code == 204
    assert client.get('/api/v1/auth/me').status_code == 401


@pytest.mark.parametrize('role', ['operator', 'viewer'])
def test_rbac_cannot_escalate(client, role):
    result = client.post('/api/v1/auth/login', json={"username": role, "password": "Test-only-randomized-scope-23!"}, headers={"x-aegis-request": "browser"})
    client.headers['x-csrf-token'] = result.json()['csrf_token']
    assert client.get('/api/v1/users').status_code == 403
    assert client.get('/api/v1/audit').status_code == 403
    assert client.post('/api/v1/users', json={"username": "evil", "password": "Password-only-test!", "role": "administrator"}).status_code == 403
    assert client.post('/api/v1/executions/'+str(uuid.uuid4())+'/approve', json={"confirm_scope_hash": "a"*64}).status_code == 403
    if role == 'viewer':
        assert client.post('/api/v1/campaigns', json={"name":"Valid name","objective":"A valid objective","laboratory_id":str(uuid.uuid4()),"test_ids":["demo-shell"]}).status_code == 403


def test_origin_size_limits_and_input_secret_redaction(client):
    assert client.post('/api/v1/auth/login', json={}, headers={"origin": "https://evil.example"}).status_code == 403
    assert client.post('/api/v1/auth/login', content='x'*262145).status_code == 413
    value='VerySensitiveNotForResponse'*10
    error=client.post('/api/v1/auth/login', json={"username":"bad name", "password":value})
    assert error.status_code == 422
    assert value not in error.text


def test_login_rate_limiting_and_audit_no_passwords(client):
    for _ in range(10):
        assert client.post('/api/v1/auth/login', json={"username":"viewer","password":"wrong-secret"}, headers={"x-aegis-request":"browser"}).status_code == 401
    assert client.post('/api/v1/auth/login', json={"username":"viewer","password":"wrong-secret"}, headers={"x-aegis-request":"browser"}).status_code == 429
    with session_factory()() as db:
        assert 'wrong-secret' not in str([a.details for a in db.scalars(select(AuditEvent))])


def test_lab_scope_change_invalidates_approval(admin):
    queued=create_queued(admin, ['demo-shell'])
    admin.post(f'/api/v1/executions/{queued["id"]}/cancel')
    pending=admin.post(f'/api/v1/campaigns/{queued["campaign_id"]}/runs', json={"idempotency_key":uuid.uuid4().hex}).json()
    approval=admin.post(f'/api/v1/executions/{pending["id"]}/approve', json={"confirm_scope_hash": pending['scope_hash']})
    assert approval.status_code == 200
    with session_factory()() as db:
        db.get(Laboratory, queued['laboratory_id']).environment_version += 1
        db.commit()
    assert admin.post(f'/api/v1/executions/{pending["id"]}/start', json={"confirm":True}).status_code == 409


def test_false_confirmation_and_arbitrary_command_fields_rejected(admin):
    run=create_queued(admin,['demo-shell'])
    assert admin.post(f'/api/v1/executions/{run["id"]}/start',json={"confirm":False}).status_code==422
    assert admin.post(f'/api/v1/executions/{run["id"]}/start',json={"confirm":True,"command":"id"}).status_code==422
    assert admin.get('/api/v1/connectors').json()['items'][1]['status']=='disconnected'
    assert admin.post('/api/v1/connectors/wazuh/test').status_code==409


def test_report_escapes_untrusted_campaign_name():
    detail={"synthetic":True,"id":"id","campaign_name":"<script>alert(1)</script>",
            "objective":"<img src=x onerror=alert(1)>","state":"COMPLETED","created_at":"2026-10-20",
            "scope":{"environment_version":1},"executions":[]}
    html=HTMLReportExporter().export(build_report(detail))
    assert '<script>alert' not in html
    assert '&lt;script&gt;' in html
    assert '<img src=x' not in html


def test_password_whitespace_is_significant(admin):
    password = '  whitespace-is-significant  '
    assert admin.post('/api/v1/users', json={'username': 'space-user', 'password': password, 'role': 'viewer'}).status_code == 201
    admin.post('/api/v1/auth/logout')
    assert admin.post('/api/v1/auth/login', json={'username': 'space-user', 'password': password}, headers={'x-aegis-request': 'browser'}).status_code == 200
