"""
Enumerate the tenant ID and company/domain name associated with an Azure Storage Account,
to ensure you're targeting storage accounts that are actually in scope.

- Tenant ID: extracted from the 401 response's WWW-Authenticate header
- Company/domain name: resolved via the Graph API's findTenantInformationByTenantId
"""

from azure.identity import InteractiveBrowserCredential

import argparse
import re
import requests
import warnings

def get_tenant_id(account):
    """
    Extract the tenant ID for a storage account via an
    unauthenticated request (containing an invalid bearer token).

    Azure returns the tenant ID in the WWW-Authenticate header
    of the resulting 401 response, e.g.:

    WWW-Authenticate: Bearer authorization_uri=https://login.microsoftonline.com/{tenant_id}/oauth2/authorize resource_id=https://storage.azure.com
    """
    url = f"https://{account}/?restype=service&comp=properties"
    headers = {
        "x-ms-version": "2020-10-02",
        "Authorization": "Bearer NotValid"
    }

    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
        return None, str(e)

    wwwauth = response.headers.get("www-authenticate")
    if not wwwauth:
        return None, "no WWW-Authenticate header in response"

    match = re.search(r'login\.microsoftonline\.com/([0-9a-fA-F-]{36})/', wwwauth)
    if not match:
        return None, "tenant ID not found in WWW-Authenticate header"

    return match.group(1), None


def get_tenant_name(tenant_id, credential):
    """
    Resolve a tenant ID to its display name and default domain via the Graph API.

    Requires the caller to be authenticated to any tenant, but does not
    require any Entra ID role on the target tenant.
    """
    token = credential.get_token("https://graph.microsoft.com/.default")

    url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')"
    headers = {"Authorization": f"Bearer {token.token}"}

    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
            return None, None, str(e)
    
    return response.json().get("displayName"), response.json().get("defaultDomainName"), None


def parse_args():
    parser = argparse.ArgumentParser(
        description = "Enumerate the tenant ID and company/domain name associated with an Azure Storage Account",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--account", type=str, help="single Azure Storage Account to check")
    group.add_argument("-f", "--file", type=str, help="file containing a list of storage accounts (one per line)")

    parser.add_argument("-r", "--resolve-domain", action="store_true", help="resolve tenant display name and default domain via Microsoft Graph")

    return parser.parse_args()

if __name__ == "__main__":

    warnings.filterwarnings(
        "ignore",
        message="response_mode='form_post' is recommended.*",
        category=UserWarning,
    )

    args = parse_args()

    # Normalize input - whether multiple accounts are provided in a file or single account via command line, it all ends up in one list
    if args.file:
        with open(args.file, "r") as f:
            accounts = [line.strip() for line in f]
    else:
        accounts = [args.account]

    credential = InteractiveBrowserCredential() if args.resolve_domain else None

    for account in accounts:
        tenant_id, error = get_tenant_id(account)

        if not tenant_id:
            print(f"[-] {account}: {error}")
            continue

        if args.resolve_domain:
            display_name, domain_name, error = get_tenant_name(tenant_id, credential)
            print(f"[+] {account} -> {tenant_id} ({display_name}, {domain_name})")
        else:
            print(f"[+] {account} -> {tenant_id}")