import os
import json
import base64
import requests
import boto3
import traceback
from kubernetes import client
from kubernetes.client import ApiClient, ApiException
from botocore.signers import RequestSigner
import datetime
import secrets 
import re
from urllib.parse import urlparse, urlunparse


# --------------------
# Team Configuration Helper
# --------------------
def get_team_config(team_name, platform="github", use_enterprise=None):
    """
    Fetches team-specific configuration (base URL, token, and username) from environment variables.

    Environment variable naming convention:

    For Enterprise instances:
    - TEAM_<TEAMNAME>_GITHUB_ENTERPRISE_URL (required for enterprise)
    - TEAM_<TEAMNAME>_GITHUB_ENTERPRISE_TOKEN (required for enterprise)
    - TEAM_<TEAMNAME>_GITHUB_ENTERPRISE_USERNAME (optional)
    - TEAM_<TEAMNAME>_GITLAB_ENTERPRISE_URL (required for enterprise)
    - TEAM_<TEAMNAME>_GITLAB_ENTERPRISE_TOKEN (required for enterprise)
    - TEAM_<TEAMNAME>_GITLAB_ENTERPRISE_USERNAME (optional)

    For Public instances (fallback if enterprise vars not set):
    - TEAM_<TEAMNAME>_GITHUB_URL (optional - if not set, uses public GitHub)
    - TEAM_<TEAMNAME>_GITHUB_TOKEN (required)
    - TEAM_<TEAMNAME>_GITHUB_USERNAME (optional)
    - TEAM_<TEAMNAME>_GITLAB_URL (optional - if not set, uses public GitLab)
    - TEAM_<TEAMNAME>_GITLAB_TOKEN (required)
    - TEAM_<TEAMNAME>_GITLAB_USERNAME (optional)

    Args:
        team_name: Name of the team (will be uppercased for env var lookup)
        platform: "github" or "gitlab"
        use_enterprise: Optional boolean to explicitly specify enterprise mode.
                       If None, auto-detects based on enterprise token presence.
                       If True, uses enterprise configuration.
                       If False, uses regular/public configuration.

    Returns:
        dict: {
            "base_url": str or None,
            "token": str,
            "username": str or None,
            "is_enterprise": bool
        }

    Raises:
        ValueError: If team configuration is not found or token is missing
    """
    if not team_name:
        raise ValueError("teamName parameter is required")

    team_upper = team_name.replace("-", "_").replace(" ", "_")
    platform_upper = platform.upper()

    print(f"[INFO] Fetching configuration for team: {team_name} (platform: {platform}, use_enterprise: {use_enterprise})")

    # First check for enterprise-specific environment variables
    enterprise_url_key = f"TEAM_{team_upper}_{platform_upper}_ENTERPRISE_URL"
    enterprise_token_key = f"TEAM_{team_upper}_{platform_upper}_ENTERPRISE_TOKEN"
    enterprise_username_key = f"TEAM_{team_upper}_{platform_upper}_ENTERPRISE_USERNAME"

    enterprise_url = os.environ.get(enterprise_url_key)
    enterprise_token = os.environ.get(enterprise_token_key)
    enterprise_username = os.environ.get(enterprise_username_key)

    # Check regular configuration as well
    base_url_key = f"TEAM_{team_upper}_{platform_upper}_URL"
    token_key = f"TEAM_{team_upper}_{platform_upper}_TOKEN"
    username_key = f"TEAM_{team_upper}_{platform_upper}_USERNAME"

    regular_base_url = os.environ.get(base_url_key)
    regular_token = os.environ.get(token_key)
    regular_username = os.environ.get(username_key)

    # Determine which configuration to use
    if use_enterprise is None:
        # Default to public/regular credentials
        is_enterprise = False
    else:
        # Use explicit flag from caller
        is_enterprise = use_enterprise

    if is_enterprise:
        # Use enterprise configuration
        base_url = enterprise_url
        token = enterprise_token
        username = enterprise_username

        print(f"[DEBUG] Selected ENTERPRISE credentials - Token key: {enterprise_token_key}, Token exists: {token is not None}, Token length: {len(token) if token else 0}")

        if not token or token.strip() == "":
            raise ValueError(
                f"Enterprise token not found for team '{team_name}' on platform '{platform}'. "
                f"Please set environment variable: {enterprise_token_key}"
            )

        if not base_url or base_url.strip() == "":
            raise ValueError(
                f"Enterprise URL not found for team '{team_name}' on platform '{platform}'. "
                f"Please set environment variable: {enterprise_url_key}"
            )

        base_url = base_url.rstrip('/')
        print(f"[INFO] Using enterprise {platform} URL for team '{team_name}': {base_url}")

        if username:
            print(f"[INFO] Using enterprise {platform} username for team '{team_name}': {username}")
    else:
        # Use regular (public) configuration
        base_url = regular_base_url
        token = regular_token
        username = regular_username

        print(f"[DEBUG] Selected REGULAR/PUBLIC credentials - Token key: {token_key}, Token exists: {token is not None}, Token length: {len(token) if token else 0}")

        if not token:
            raise ValueError(
                f"Token not found for team '{team_name}' on platform '{platform}'. "
                f"Please set environment variable: {token_key} or {enterprise_token_key}"
            )

        if base_url and base_url.strip() != "":
            base_url = base_url.rstrip('/')
            print(f"[INFO] Using custom {platform} URL for team '{team_name}': {base_url}")
        else:
            print(f"[INFO] Using public {platform} for team '{team_name}'")

        if username:
            print(f"[INFO] Using {platform} username for team '{team_name}': {username}")

    return {
        "base_url": base_url,
        "token": token,
        "username": username,
        "is_enterprise": is_enterprise
    }

# ======================================================================
# GITHUB FUNCTIONS
# ======================================================================

# --------------------
# GitHub API Helper
# --------------------
def get_github_api_base_url(base_url=None):
    """
    Returns the appropriate GitHub API base URL.
    
    Args:
        base_url: Custom base URL for enterprise GitHub (optional)
    
    Returns:
        str: API base URL
    """
    if base_url:
        # Enterprise URL - expecting format like https://your-ghe-instance.com/api/v3
        return base_url.rstrip('/')
    else:
        return "https://api.github.com"


# --------------------
# GitHub Repo Listing
# --------------------
def github_list_repositories(name, target_type, token, base_url=None, page=1, per_page=100, visibility=None, search=None):
    """
    Fetches a list of repositories for a given GitHub user or organization,
    supporting both public and enterprise GitHub with visibility filtering.

    Args:
        name: Username or organization name
        target_type: "user" or "org"
        token: GitHub access token (team-specific)
        base_url: Custom GitHub base URL for enterprise (optional)
        page: Page number for pagination
        per_page: Number of results per page (default: 100)
        visibility: Filter by visibility - "all", "public", "private", or "internal"
        search: Optional repository name to filter by (case-insensitive partial match)
    """
    is_enterprise = base_url is not None
    print(f"[INFO] Fetching GitHub repositories (Enterprise: {is_enterprise}, Visibility: {visibility}, Search: {search})...")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    api_base_url = get_github_api_base_url(base_url)
    formatted_repos = []
    page_num = 1

    # If search is provided, fetch *all* repos to ensure we don't miss matches
    fetch_all = search is not None and search.strip() != ""

    print(f"[INFO] Mode: {'Full repository fetch (search enabled)' if fetch_all else 'Paged fetch'}")

    while True:
        # Build API URL for the current page
        if target_type == "user":
            repos_url = f"{api_base_url}/user/repos?per_page={per_page}&page={page_num}"
            vis_param = visibility if visibility and visibility != "internal" else "all"
            repos_url += f"&visibility={vis_param}"
        else:
            repos_url = f"{api_base_url}/orgs/{name}/repos?per_page={per_page}&page={page_num}"
            repos_url += f"&type={visibility or 'all'}"

        print(f"[DEBUG] Calling URL: {repos_url}")
        response = requests.get(repos_url, headers=headers)

        if response.status_code != 200:
            print(f"[ERROR] GitHub API error ({response.status_code}): {response.text}")
            raise Exception(f"GitHub API error ({response.status_code}): {response.text}")

        data = response.json()
        if not data:
            print(f"[INFO] No more repositories found at page {page_num}.")
            break

        for repo in data:
            formatted_repos.append({
                "name": repo.get("full_name"),
                "cloneUrl": repo.get("clone_url"),
                "htmlUrl": repo.get("html_url"),
                "language": "Github",
                "private": repo.get("private", False),
                "visibility": repo.get("visibility", "public")
            })

        # Check for next page
        link_header = response.headers.get("Link", "")
        has_next = 'rel="next"' in link_header

        # If search mode is on, always continue until all repos are fetched
        if not fetch_all and (not has_next or page_num >= page):
            break

        page_num += 1

        # Optional short-circuit: stop early if a match is already found
        if fetch_all and any(search.lower() in repo["name"].lower() for repo in formatted_repos):
            pass

        # Safety: avoid infinite loops
        if page_num > 100:  # 100 pages * 100 repos = 10,000 max
            print("[WARN] Reached pagination limit (10,000 repos). Stopping early.")
            break

    # Apply search filter if requested
    if search:
        search_lower = search.lower()
        filtered_repos = [
            repo for repo in formatted_repos
            if search_lower in repo.get("name", "").lower()
        ]
        print(f"[INFO] Search filter applied: Found {len(filtered_repos)} matching repository(ies)")
        return {"content": filtered_repos, "hasNext": False}

    print(f"[INFO] Retrieved {len(formatted_repos)} repositories total.")
    return {"content": formatted_repos, "hasNext": has_next if not fetch_all else False}


# --------------------
# GitHub Branch Listing
# --------------------
def github_list_branches(repo_url, token, base_url=None):
    """
    Fetches all branch names for a given GitHub repository URL,
    supporting both public and enterprise GitHub.
    
    Args:
        repo_url: GitHub repository URL
        token: GitHub access token (team-specific)
        base_url: Custom GitHub base URL for enterprise (optional)
    """
    is_enterprise = base_url is not None
    print(f"[INFO] Fetching branches for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Generic regex to extract owner/repo from public or enterprise URLs
    match = re.search(r"https://[^/]+/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitHub repository URL format.")

    owner, repo_name = match.groups()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    
    api_base_url = get_github_api_base_url(base_url)
    branches = []
    page = 1
    
    while True:
        branches_url = f"{api_base_url}/repos/{owner}/{repo_name}/branches?per_page=100&page={page}"
        response = requests.get(branches_url, headers=headers)

        if response.status_code != 200:
            print(f"[ERROR] GitHub API error ({response.status_code}): {response.text}")
            raise Exception(f"GitHub API error ({response.status_code}): {response.text}")

        data = response.json()
        if not data:
            break

        for branch in data:
            branches.append(branch.get("name"))
        page += 1

    print(f"[INFO] Retrieved {len(branches)} branches.")
    return {"content": branches}


# --------------------
# GitHub Default Branch
# --------------------
def github_get_default_branch(repo_url, token, base_url=None):
    """
    Fetches the default branch for a given GitHub repository URL,
    supporting both public and enterprise GitHub.
    
    Args:
        repo_url: GitHub repository URL
        token: GitHub access token (team-specific)
        base_url: Custom GitHub base URL for enterprise (optional)
    """
    is_enterprise = base_url is not None
    print(f"[INFO] Fetching default branch for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Generic regex to extract owner/repo from public or enterprise URLs
    match = re.search(r"https://[^/]+/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitHub repository URL format.")

    owner, repo_name = match.groups()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    
    api_base_url = get_github_api_base_url(base_url)
    repo_api_url = f"{api_base_url}/repos/{owner}/{repo_name}"
    response = requests.get(repo_api_url, headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] GitHub API error ({response.status_code}): {response.text}")
        raise Exception(f"GitHub API error ({response.status_code}): {response.text}")

    default_branch = response.json().get("default_branch")
    print(f"[INFO] Retrieved default branch: {default_branch}")
    return {"content": default_branch}


# ======================================================================
# GITLAB FUNCTIONS
# ======================================================================

# --------------------
# GitLab API Helper
# --------------------
def get_gitlab_api_base_url(base_url=None):
    """
    Returns the appropriate GitLab API base URL.

    Args:
        base_url: Custom base URL for enterprise GitLab (optional)

    Returns:
        str: API base URL (always includes /api/v4)
    """
    if not base_url:
        return "https://gitlab.com/api/v4"

    base_url = base_url.rstrip('/')

    # If the URL is just https://gitlab.com (public GitLab without /api/v4), treat as public
    if base_url == "https://gitlab.com":
        return "https://gitlab.com/api/v4"

    # For any URL, ensure /api/v4 is present
    if not base_url.endswith('/api/v4'):
        base_url = f"{base_url}/api/v4"

    return base_url


# --------------------
# GitLab Repo Listing
# --------------------
def gitlab_list_repositories(name, target_type, token, base_url=None, page=0, per_page=50, search=None):
    """
    Fetches a list of repositories for a given GitLab user or group,
    supporting both public and enterprise GitLab.

    Args:
        name: Username or group name
        target_type: "user" or "org" (org = group in GitLab)
        token: GitLab access token (team-specific)
        base_url: Custom GitLab base URL for enterprise (optional)
        page: 0-based page number from client (will be converted to 1-based for GitLab)
        per_page: Number of items per page (max 100 for GitLab API)
        search: Optional repository name to search for (uses GitLab's native search)
    """
    # Determine if this is truly enterprise (not just https://gitlab.com)
    is_enterprise = base_url is not None and base_url.rstrip('/') not in ["https://gitlab.com", "https://gitlab.com/api/v4"]
    print(f"[INFO] Fetching GitLab repositories (Enterprise: {is_enterprise}, Search: {search})...")

    headers = {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json"
    }

    api_base_url = get_gitlab_api_base_url(base_url)

    # Convert 0-based pagination (from client) to 1-based (GitLab API)
    gitlab_page = page + 1

    # Ensure per_page is within GitLab's limits (1-100)
    per_page = min(max(1, per_page), 100)

    print(f"[DEBUG] Client page: {page}, GitLab page: {gitlab_page}, per_page: {per_page}")

    if target_type == "user":
        # For user repos, we can use the /projects endpoint with membership filter

        if search and search.strip():
            # Use GitLab's native search API for projects
            # This searches across all projects the user has access to
            search_url = f"{api_base_url}/projects?membership=true&search={requests.utils.quote(search)}&per_page={per_page}&page={gitlab_page}"
            print(f"[DEBUG] Using GitLab native search: {search_url}")

            response = requests.get(search_url, headers=headers)

            if response.status_code != 200:
                print(f"[ERROR] GitLab API error ({response.status_code}): {response.text}")
                raise Exception(f"GitLab API error ({response.status_code}): {response.text}")

            has_next = response.headers.get("X-Next-Page", "").strip() != ""
            repos = response.json()

            formatted_repos = []
            for repo in repos:
                formatted_repos.append({
                    "name": repo.get("path_with_namespace"),
                    "cloneUrl": repo.get("http_url_to_repo"),
                    "htmlUrl": repo.get("web_url"),
                    "language": "Gitlab",
                    "private": repo.get("visibility") == "private",
                    "visibility": repo.get("visibility", "public")
                })

            print(f"[INFO] GitLab search returned {len(formatted_repos)} matching repositories")
            return {"content": formatted_repos, "hasNext": has_next}

        else:
            # No search - fetch owned + contributed projects

            # Get user ID first
            user_url = f"{api_base_url}/users?username={name}"
            user_response = requests.get(user_url, headers=headers)
            if user_response.status_code != 200 or not user_response.json():
                print(f"[ERROR] GitLab API error fetching user: {user_response.text}")
                raise Exception(f"GitLab API error fetching user: {user_response.text}")

            user_id = user_response.json()[0]['id']

            # Fetch owned projects
            owned_repos_url = f"{api_base_url}/users/{user_id}/projects?per_page={per_page}&page={gitlab_page}"
            print(f"[DEBUG] Fetching owned projects: {owned_repos_url}")
            owned_response = requests.get(owned_repos_url, headers=headers)

            if owned_response.status_code != 200:
                print(f"[ERROR] GitLab API error fetching owned repos ({owned_response.status_code}): {owned_response.text}")
                raise Exception(f"GitLab API error ({owned_response.status_code}): {owned_response.text}")

            owned_has_next = owned_response.headers.get("X-Next-Page", "").strip() != ""
            owned_repos = owned_response.json()

            # Fetch contributed projects
            contributed_repos_url = f"{api_base_url}/projects?membership=true&owned=false&per_page={per_page}&page={gitlab_page}"
            print(f"[DEBUG] Fetching contributed projects: {contributed_repos_url}")
            contributed_response = requests.get(contributed_repos_url, headers=headers)

            contributed_repos = []
            contributed_has_next = False

            if contributed_response.status_code == 200:
                contributed_repos = contributed_response.json()
                contributed_has_next = contributed_response.headers.get("X-Next-Page", "").strip() != ""
                print(f"[INFO] Retrieved {len(contributed_repos)} contributed repositories")
            else:
                print(f"[WARN] Could not fetch contributed projects ({contributed_response.status_code}): {contributed_response.text}")

            # Combine and deduplicate
            all_repos = owned_repos + contributed_repos
            seen_paths = set()
            unique_repos = []
            for repo in all_repos:
                path = repo.get("path_with_namespace")
                if path not in seen_paths:
                    seen_paths.add(path)
                    unique_repos.append(repo)

            has_next = owned_has_next or contributed_has_next

            formatted_repos = []
            for repo in unique_repos:
                formatted_repos.append({
                    "name": repo.get("path_with_namespace"),
                    "cloneUrl": repo.get("http_url_to_repo"),
                    "htmlUrl": repo.get("web_url"),
                    "language": "Gitlab",
                    "private": repo.get("visibility") == "private",
                    "visibility": repo.get("visibility", "public")
                })

            print(f"[INFO] Retrieved {len(formatted_repos)} total repositories (owned + contributed, deduplicated)")
            return {"content": formatted_repos, "hasNext": has_next}

    else:
        # For groups (orgs in GitLab)

        if search and search.strip():
            # Use group search API
            # First, we need to get the group ID
            group_url = f"{api_base_url}/groups/{requests.utils.quote(name, safe='')}"
            group_response = requests.get(group_url, headers=headers)

            if group_response.status_code != 200:
                print(f"[ERROR] GitLab API error fetching group ({group_response.status_code}): {group_response.text}")
                raise Exception(f"GitLab API error ({group_response.status_code}): {group_response.text}")

            group_id = group_response.json().get("id")

            # Use group search endpoint
            search_url = f"{api_base_url}/groups/{group_id}/search?scope=projects&search={requests.utils.quote(search)}&per_page={per_page}&page={gitlab_page}"
            print(f"[DEBUG] Using GitLab group search: {search_url}")

            response = requests.get(search_url, headers=headers)

            if response.status_code != 200:
                print(f"[ERROR] GitLab API error ({response.status_code}): {response.text}")
                raise Exception(f"GitLab API error ({response.status_code}): {response.text}")

            has_next = response.headers.get("X-Next-Page", "").strip() != ""
            repos = response.json()

            formatted_repos = []
            for repo in repos:
                formatted_repos.append({
                    "name": repo.get("path_with_namespace"),
                    "cloneUrl": repo.get("http_url_to_repo"),
                    "htmlUrl": repo.get("web_url"),
                    "language": "Gitlab",
                    "private": repo.get("visibility") == "private",
                    "visibility": repo.get("visibility", "public")
                })

            print(f"[INFO] GitLab group search returned {len(formatted_repos)} matching repositories")
            return {"content": formatted_repos, "hasNext": has_next}

        else:
            # No search - normal group project listing
            repos_url = f"{api_base_url}/groups/{name}/projects?per_page={per_page}&page={gitlab_page}&include_subgroups=true"
            print(f"[DEBUG] Calling URL: {repos_url}")

            response = requests.get(repos_url, headers=headers)

            if response.status_code != 200:
                print(f"[ERROR] GitLab API error ({response.status_code}): {response.text}")
                raise Exception(f"GitLab API error ({response.status_code}): {response.text}")

            has_next = response.headers.get("X-Next-Page", "").strip() != ""

            formatted_repos = []
            for repo in response.json():
                formatted_repos.append({
                    "name": repo.get("path_with_namespace"),
                    "cloneUrl": repo.get("http_url_to_repo"),
                    "htmlUrl": repo.get("web_url"),
                    "language": "Gitlab",
                    "private": repo.get("visibility") == "private",
                    "visibility": repo.get("visibility", "public")
                })

            print(f"[INFO] Retrieved {len(formatted_repos)} repositories")
            return {"content": formatted_repos, "hasNext": has_next}


# --------------------
# GitLab Branch Listing
# --------------------
def gitlab_list_branches(repo_url, token, base_url=None):
    """
    Fetches all branch names for a given GitLab repository URL,
    supporting both public and enterprise GitLab.

    Args:
        repo_url: GitLab repository URL
        token: GitLab access token (team-specific)
        base_url: Custom GitLab base URL for enterprise (optional)
    """
    # Determine if this is truly enterprise (not just https://gitlab.com)
    is_enterprise = base_url is not None and base_url.rstrip('/') not in ["https://gitlab.com", "https://gitlab.com/api/v4"]
    print(f"[INFO] Fetching branches for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Extract project path from GitLab URL
    match = re.search(r"https://[^/]+/(.+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitLab repository URL format.")

    project_path = match.group(1)
    # URL encode the project path for API calls
    encoded_project_path = requests.utils.quote(project_path, safe='')

    headers = {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json"
    }
    
    api_base_url = get_gitlab_api_base_url(base_url)
    branches = []
    page = 1
    
    while True:
        branches_url = f"{api_base_url}/projects/{encoded_project_path}/repository/branches?per_page=100&page={page}"
        response = requests.get(branches_url, headers=headers)

        if response.status_code != 200:
            print(f"[ERROR] GitLab API error ({response.status_code}): {response.text}")
            raise Exception(f"GitLab API error ({response.status_code}): {response.text}")

        data = response.json()
        if not data:
            break

        for branch in data:
            branches.append(branch.get("name"))
        
        # Check if there's a next page
        if not response.headers.get("X-Next-Page", "").strip():
            break
        
        page += 1

    print(f"[INFO] Retrieved {len(branches)} branches.")
    return {"content": branches}


# --------------------
# GitLab Default Branch
# --------------------
def gitlab_get_default_branch(repo_url, token, base_url=None):
    """
    Fetches the default branch for a given GitLab repository URL,
    supporting both public and enterprise GitLab.

    Args:
        repo_url: GitLab repository URL
        token: GitLab access token (team-specific)
        base_url: Custom GitLab base URL for enterprise (optional)
    """
    # Determine if this is truly enterprise (not just https://gitlab.com)
    is_enterprise = base_url is not None and base_url.rstrip('/') not in ["https://gitlab.com", "https://gitlab.com/api/v4"]
    print(f"[INFO] Fetching default branch for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Extract project path from GitLab URL
    match = re.search(r"https://[^/]+/(.+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitLab repository URL format.")

    project_path = match.group(1)
    # URL encode the project path for API calls
    encoded_project_path = requests.utils.quote(project_path, safe='')

    headers = {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json"
    }
    
    api_base_url = get_gitlab_api_base_url(base_url)
    repo_api_url = f"{api_base_url}/projects/{encoded_project_path}"
    response = requests.get(repo_api_url, headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] GitLab API error ({response.status_code}): {response.text}")
        raise Exception(f"GitLab API error ({response.status_code}): {response.text}")

    default_branch = response.json().get("default_branch")
    print(f"[INFO] Retrieved default branch: {default_branch}")
    return {"content": default_branch}


# ======================================================================
# EKS FUNCTIONS
# ======================================================================

# --------------------
# EKS Token Generator
# --------------------
def get_eks_token(cluster_name, region):
    """
    Generates a presigned STS URL for EKS authentication.
    """
    print("[INFO] Generating EKS token with custom signing...")
    try:
        session = boto3.session.Session()
        sts_client = session.client('sts', region_name=region)
        service_model = sts_client.meta.service_model

        signer = RequestSigner(
            service_model.service_id, region, 'sts', 'v4',
            session.get_credentials(), session.events
        )
        request_dict = {
            'method': 'GET',
            'url': f'https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
            'body': {}, 'headers': {'x-k8s-aws-id': cluster_name}, 'context': {}
        }
        presigned_url = signer.generate_presigned_url(
            request_dict=request_dict, expires_in=60, operation_name='GetCallerIdentity'
        )
        token = 'k8s-aws-v1.' + base64.urlsafe_b64encode(
            presigned_url.encode('utf-8')
        ).decode('utf-8').rstrip('=')

        print("[INFO] EKS token generated successfully.")
        return token

    except Exception as e:
        print(f"[ERROR] Failed to generate EKS token: {str(e)}")
        raise


# --------------------
# EKS API Configuration
# --------------------
def configure_kubernetes_client(cluster_name, region):
    """
    Configures the Kubernetes client to communicate with an EKS cluster.
    """
    print(f"[INFO] Configuring Kubernetes client for cluster: {cluster_name}")
    eks_client = boto3.client('eks', region_name=region)
    cluster_info = eks_client.describe_cluster(name=cluster_name)
    endpoint = cluster_info['cluster']['endpoint']
    cert_authority = cluster_info['cluster']['certificateAuthority']['data']

    configuration = client.Configuration()
    configuration.host = endpoint
    configuration.ssl_ca_cert = write_temp_cert(cert_authority)
    configuration.api_key['authorization'] = get_eks_token(cluster_name, region)
    configuration.api_key_prefix['authorization'] = 'Bearer'

    client.Configuration.set_default(configuration)
    print("[INFO] Kubernetes client configured.")


def write_temp_cert(cert_data):
    """
    Writes the cluster's certificate authority data to a temporary file.
    """
    import tempfile
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(base64.b64decode(cert_data))
    cert_file.close()
    return cert_file.name


# --------------------
# Job Trigger Function
# --------------------
def trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list):
    namespace = "default"
    """
    Triggers a Kubernetes Job on an EKS cluster using the Kubernetes Python client.
    """
    print("[INFO] Setting up Kubernetes client...")
    configure_kubernetes_client(cluster_name, region)

    batch_v1 = client.BatchV1Api()

    print("[INFO] Defining Kubernetes job spec...")

    # Container security context for non-root execution
    container_security_context = client.V1SecurityContext(
        allow_privilege_escalation=False,
        run_as_non_root=True
    )

    # Resource requests and limits from environment variables
    resources = client.V1ResourceRequirements(
        requests={
            "cpu": os.environ.get("K8_RESOURCES_REQUEST_CPU", "2000m"),
            "memory": os.environ.get("K8_RESOURCES_REQUEST_MEMORY", "3Gi"),
        },
        limits={
            "memory": os.environ.get("K8_RESOURCES_LIMIT_MEMORY", "8Gi"),
        }
    )

    container = client.V1Container(
        name="scanner", image=image, args=args_list,
        env=[client.V1EnvVar(name=k, value=v) for k, v in env_vars.items()],
        security_context=container_security_context,
        resources=resources
    )

    # Pod security context for non-root user (UID 1000)
    pod_security_context = client.V1PodSecurityContext(
        run_as_user=1000,
        run_as_group=1000,
        fs_group=1000
    )

    pod_spec = client.V1PodSpec(
        restart_policy="Never",
        containers=[container],
        image_pull_secrets=[client.V1LocalObjectReference(name="image-secret")],
        security_context=pod_security_context
    )
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(name=job_name), spec=pod_spec
    )
    spec = client.V1JobSpec(
        template=template, backoff_limit=1, ttl_seconds_after_finished=240
    )
    job = client.V1Job(
        api_version="batch/v1", kind="Job",
        metadata=client.V1ObjectMeta(name=job_name), spec=spec
    )

    try:
        print("[INFO] Submitting job to Kubernetes cluster...")
        batch_v1.create_namespaced_job(namespace=namespace, body=job)
        print(f"[SUCCESS] Job '{job_name}' successfully created in namespace '{namespace}'.")
    except ApiException as e:
        print(f"[ERROR] Exception when calling BatchV1Api->create_namespaced_job: {e}")
        raise


# --------------------
# Job Status Check Function
# --------------------
def check_job_status(cluster_name, region, job_name):
    """
    Checks the status of a Kubernetes Job on an EKS cluster.
    """
    print(f"[INFO] Checking status for job: {job_name}")
    configure_kubernetes_client(cluster_name, region)

    batch_v1 = client.BatchV1Api()

    try:
        job = batch_v1.read_namespaced_job(name=job_name, namespace="default")
        status = job.status

        result = {
            "jobName": job_name,
            "active": status.active if status.active else 0,
            "succeeded": status.succeeded if status.succeeded else 0,
            "failed": status.failed if status.failed else 0,
            "startTime": status.start_time.isoformat() if status.start_time else None,
            "completionTime": status.completion_time.isoformat() if status.completion_time else None
        }

        if status.conditions:
            result["conditions"] = [
                {
                    "type": c.type,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message
                } for c in status.conditions
            ]

        print(f"[INFO] Job status retrieved: {result}")
        return {"content": result}

    except ApiException as e:
        if e.status == 404:
            print(f"[INFO] Job '{job_name}' not found.")
            return {"content": {"jobName": job_name, "status": "Not Found"}}
        else:
            print(f"[ERROR] Exception when calling BatchV1Api->read_namespaced_job: {e}")
            raise


# ======================================================================
# LAMBDA HANDLER
# ======================================================================

def lambda_handler(event, context):
    """
    AWS Lambda handler function to process GitHub/GitLab and EKS-related actions.
    Supports multi-team configuration via environment variables.
    """
    print("[INFO] Lambda invocation started.")
    print(f"[DEBUG] Received event: {json.dumps(event, indent=2)}")

    try:
        # Parse request body
        if 'body' in event and isinstance(event['body'], str):
            body = json.loads(event['body'])
        elif 'body' in event and isinstance(event['body'], dict):
            body = event['body']
        else:
            body = event
        
        print(f"[DEBUG] Parsed body: {json.dumps(body, indent=2)}")

        # Extract action
        action = body.get("action")
        if not action:
            return {
                "statusCode": 400, 
                "body": json.dumps({"error": "Missing required parameter: 'action'."})
            }

        # Extract teamName (required for all actions)
        team_name = body.get("teamName")
        if not team_name:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing required parameter: 'teamName'."})
            }

        # Extract is-enterprise flag (optional, can be passed to control which credentials to use)
        # Check both top level and inside 'args' object
        use_enterprise = body.get("is-enterprise")
        if use_enterprise is None and "args" in body:
            use_enterprise = body["args"].get("is-enterprise")

        if use_enterprise is not None:
            # Convert to boolean if string
            if isinstance(use_enterprise, str):
                use_enterprise = use_enterprise.lower() in ['true', '1', 'yes']
            else:
                use_enterprise = bool(use_enterprise)

        print(f"[DEBUG] is-enterprise flag from event: {use_enterprise} (checked top level and args)")
        print(f"[INFO] Processing action '{action}' for team '{team_name}'")

        # ======================
        # Action: list_repos
        # ======================
        if action == "list_repos":
            print("[INFO] Action: list_repos")
            
            # Get repo type to determine platform
            repo_type = body.get("type")
            platform = body.get("platform", "github").lower()  # Default to github for backward compatibility
            
            # Get team-specific configuration
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}
            
            # Use username from team config, fallback to request body if not set
            name = team_config.get("username") or body.get("name", "")
            
            if not name:
                return {
                    "statusCode": 400, 
                    "body": json.dumps({
                        "error": f"Username not found for team '{team_name}' on platform '{platform}'. "
                                f"Please set environment variable: TEAM_{team_name.replace('-', '_').replace(' ', '_')}_{platform.upper()}_USERNAME "
                                f"or provide 'name' in the request body."
                    })
                }
            
            target_type = repo_type if repo_type in ["user", "org"] else "user"
            page = int(body.get("page", 0))  # 0-based pagination from client
            page_size = int(body.get("pageSize", 50))
            search = body.get("search")  # Extract search parameter for both platforms

            if platform == "github":
                visibility = body.get("visibility", "all")

                # Validate visibility parameter
                valid_visibilities = ["all", "public", "private", "internal"]
                if visibility not in valid_visibilities:
                    return {
                        "statusCode": 400,
                        "body": json.dumps({"error": f"Invalid 'visibility' parameter. Must be one of: {', '.join(valid_visibilities)}"})
                    }

                print(f"[INFO] Fetching GitHub repos for type='{target_type}', name='{name}', visibility='{visibility}', search='{search}'")

                repos_data = github_list_repositories(
                    name,
                    target_type,
                    team_config["token"],
                    base_url=team_config["base_url"],
                    page=page + 1,  # GitHub uses 1-based pagination
                    per_page=page_size,
                    visibility=visibility,
                    search=search
                )
            elif platform == "gitlab":
                print(f"[INFO] Fetching GitLab repos for type='{target_type}', name='{name}', search='{search}'")

                repos_data = gitlab_list_repositories(
                    name,
                    target_type,
                    team_config["token"],
                    base_url=team_config["base_url"],
                    page=page,  # GitLab function now handles 0-based to 1-based conversion internally
                    per_page=page_size,
                    search=search
                )
            else:
                return {"statusCode": 400, "body": json.dumps({"error": f"Invalid platform: '{platform}'. Must be 'github' or 'gitlab'."})}

            return {"statusCode": 200, "body": json.dumps(repos_data)}

        # ======================
        # Action: list_branches
        # ======================
        elif action == "list_branches":
            print("[INFO] Action: list_branches")
            
            repo_url = body.get("repo_url")
            repo_type = body.get("type", "").upper()

            if not repo_url:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter: 'repo_url'"})}
            
            if repo_type == "GITHUB":
                platform = "github"
            elif repo_type == "GITLAB":
                platform = "gitlab"
            else:
                return {"statusCode": 400, "body": json.dumps({"error": "Invalid 'type'. Must be 'GITHUB' or 'GITLAB'."})}

            # Get team-specific configuration
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

            if platform == "github":
                branch_data = github_list_branches(
                    repo_url, 
                    team_config["token"],
                    base_url=team_config["base_url"]
                )
            else:  # gitlab
                branch_data = gitlab_list_branches(
                    repo_url,
                    team_config["token"],
                    base_url=team_config["base_url"]
                )

            return {"statusCode": 200, "body": json.dumps(branch_data)}

        # ======================
        # Action: default_branch
        # ======================
        elif action == "default_branch":
            print("[INFO] Action: default_branch")
            
            repo_url = body.get("repo_url")
            repo_type = body.get("type", "").upper()

            if not repo_url:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter: 'repo_url'"})}
            
            if repo_type == "GITHUB":
                platform = "github"
            elif repo_type == "GITLAB":
                platform = "gitlab"
            else:
                return {"statusCode": 400, "body": json.dumps({"error": "Invalid 'type'. Must be 'GITHUB' or 'GITLAB'."})}

            # Get team-specific configuration
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

            if platform == "github":
                default_branch_data = github_get_default_branch(
                    repo_url, 
                    team_config["token"],
                    base_url=team_config["base_url"]
                )
            else:  # gitlab
                default_branch_data = gitlab_get_default_branch(
                    repo_url,
                    team_config["token"],
                    base_url=team_config["base_url"]
                )

            return {"statusCode": 200, "body": json.dumps(default_branch_data)}

        # ======================
        # Action: trigger_scan
        # ======================
        elif action == "trigger_scan":
            print("[INFO] Action: trigger_scan")
            
            args_dict = body.get("args", {})
            if not args_dict:
                return {"statusCode": 400, "body": json.dumps({"error": "Job arguments ('args') dictionary cannot be empty."})}
            
            job_id = args_dict.get("job-id")
            if not job_id:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'job-id' in 'args'."})}

            # Determine platform from repo-type
            repo_type = args_dict.get("repo-type", "").upper()
            platform = body.get("platform", "").lower()


            # Get team-specific configuration
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

            job_name = f"cdefense-hbyrid-{job_id}"
            print(f"[INFO] Constructed job name from client-provided id: {job_name}")

            image = os.environ.get("CLI_IMAGE")
            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps({"error": "EKS_CLUSTER_NAME environment variable not set."})}

            env_vars = body.get("env", {})
            
            # Construct authenticated URL for private repositories
            repo_url = args_dict.get("repo-url")
            if repo_url:
                url_without_scheme = repo_url.replace("https://", "").replace("http://", "")
                
                if platform == "github":
                    authenticated_url = f"https://{team_config['token']}@{url_without_scheme}"
                    env_vars["GITHUB_TOKEN"] = team_config["token"]
                    if team_config["base_url"]:
                        env_vars["GITHUB_ENTERPRISE_URL"] = team_config["base_url"]
                elif platform == "gitlab":
                    authenticated_url = f"https://oauth2:{team_config['token']}@{url_without_scheme}"
                    env_vars["GITLAB_TOKEN"] = team_config["token"]
                    if team_config["base_url"]:
                        env_vars["GITLAB_ENTERPRISE_URL"] = team_config["base_url"]
                
                env_vars["GIT_REPO"] = authenticated_url
                print(f"[INFO] Constructed authenticated GIT_REPO URL for private repository on {platform}.")

            env_vars["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID_HYBRID")
            env_vars["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY_HYBRID")
            env_vars["BUCKET_NAME"] = os.environ.get("BUCKET_NAME_HYBRID")
            env_vars["AWS_REGION"] = os.environ.get("AWS_REGION_HYBRID")

            args_list = ["full"]
            
            # Add --is-enterprise flag if using enterprise
            if team_config["is_enterprise"]:
                args_list.append("--is-enterprise")
            
            for key, value in args_dict.items():
                args_list.append(f"--{key}={str(value)}")

            print(f"[INFO] Constructed job arguments: {args_list}")
            print("[INFO] Triggering EKS job...")
            trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list)
            print("[SUCCESS] Job submission process completed.")
            return {"statusCode": 202, "body": json.dumps({"message": f"K8s job '{job_name}' accepted for processing."})}

        # ======================
        # Action: trigger_scan_public
        # ======================
        elif action == "trigger_scan_public":
            print("[INFO] Action: trigger_scan_public")
            
            args_dict = body.get("args", {})
            if not args_dict:
                return {"statusCode": 400, "body": json.dumps({"error": "Job arguments ('args') dictionary cannot be empty."})}
            
            job_id = args_dict.get("job-id")
            if not job_id:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'job-id' in 'args'."})}

            repo_url = args_dict.get("repo-url")
            if not repo_url:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'repo-url' for public repository scan."})}

            # Determine platform from repo-type
            repo_type = args_dict.get("repo-type", "").upper()
            if repo_type in ["GITHUB", "BRANCH"]:
                platform = "github"
            elif repo_type == "GITLAB":
                platform = "gitlab"
            else:
                # Try to auto-detect from URL
                if "gitlab" in repo_url.lower():
                    platform = "gitlab"
                else:
                    platform = "github"

            # Get team-specific configuration (for enterprise URL if needed)
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

            job_name = f"cdefense-public-{job_id}"
            print(f"[INFO] Constructed job name for public repo scan: {job_name}")

            image = os.environ.get("CLI_IMAGE")
            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps({"error": "EKS_CLUSTER_NAME environment variable not set."})}

            env_vars = body.get("env", {})
            
            env_vars["GIT_REPO"] = repo_url
            print(f"[INFO] Using public repository URL: {repo_url}")

            # Add team-specific enterprise URL if applicable
            if platform == "github" and team_config["base_url"]:
                env_vars["GITHUB_ENTERPRISE_URL"] = team_config["base_url"]
            elif platform == "gitlab" and team_config["base_url"]:
                env_vars["GITLAB_ENTERPRISE_URL"] = team_config["base_url"]
            
            env_vars["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID_HYBRID")
            env_vars["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY_HYBRID")
            env_vars["BUCKET_NAME"] = os.environ.get("BUCKET_NAME_HYBRID")
            env_vars["AWS_REGION"] = os.environ.get("AWS_REGION_HYBRID")

            args_list = ["full"]
            
            # Add --is-enterprise flag if using enterprise
            if team_config["is_enterprise"]:
                args_list.append("--is-enterprise")
            
            for key, value in args_dict.items():
                args_list.append(f"--{key}={str(value)}")

            print(f"[INFO] Constructed job arguments for public repo: {args_list}")
            print("[INFO] Triggering EKS job for public repository scan...")
            trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list)
            print("[SUCCESS] Public repository scan job submission completed.")
            return {"statusCode": 202, "body": json.dumps({"message": f"K8s job '{job_name}' accepted for processing."})}

        # ======================
        # Action: trigger_ai_sast_scan (HYBRID MODE)
        # ======================
        elif action == "trigger_ai_sast_scan":
            print("[INFO] Action: trigger_ai_sast_scan (HYBRID MODE)")

            args_dict = body.get("args", {})
            if not args_dict:
                return {"statusCode": 400, "body": json.dumps({"error": "Job arguments ('args') dictionary cannot be empty."})}

            # Get required parameters from args
            job_id = args_dict.get("job-id")
            if not job_id:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'job-id' in 'args'."})}

            batch_id = args_dict.get("batch-id")
            if not batch_id:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'batch-id' in 'args' for AI-SAST scan."})}

            repo_url = args_dict.get("repo-url")
            if not repo_url:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter 'repo-url' in 'args' for AI-SAST scan."})}

            # Determine platform from repo-type or body
            repo_type = args_dict.get("repo-type", "").upper()
            platform = body.get("platform", "").lower()

            if not platform:
                if repo_type in ["GITHUB", "BRANCH"]:
                    platform = "github"
                elif repo_type == "GITLAB":
                    platform = "gitlab"
                else:
                    # Try to auto-detect from URL
                    if "gitlab" in repo_url.lower():
                        platform = "gitlab"
                    else:
                        platform = "github"

            print(f"[INFO] Detected platform: {platform}")

            # Get team-specific configuration
            try:
                team_config = get_team_config(team_name, platform=platform, use_enterprise=use_enterprise)
            except ValueError as e:
                return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

            # Construct the job name for AI-SAST scan
            job_name = f"ai-sast-{job_id}"
            print(f"[INFO] Constructed AI-SAST job name: {job_name}")

            # Use dedicated AI-SAST image
            image = os.environ.get("AI_SAST_IMAGE")
            if not image:
                return {"statusCode": 500, "body": json.dumps({"error": "AI_SAST_IMAGE environment variable not set."})}

            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps({"error": "EKS_CLUSTER_NAME environment variable not set."})}

            # Set up environment variables for AI-SAST scanner
            # Start with any env vars passed from the ai-sast-service
            env_vars = body.get("env", {})

            # Handle repository authentication for private repos
            is_enterprise = team_config.get("is_enterprise", False)
            url_without_scheme = repo_url.replace("https://", "").replace("http://", "")

            parsed_repo = urlparse(repo_url)

            # Always strip any embedded creds from backend URL and rebuild with customer token from env/team config
            host_netloc = parsed_repo.hostname or ""
            if parsed_repo.port:
                host_netloc = f"{host_netloc}:{parsed_repo.port}"
            if not host_netloc:
                host_netloc = repo_url.replace("https://", "").replace("http://", "")

            if platform == "github":
                authenticated_netloc = f"{team_config['token']}@{host_netloc}"
                rebuilt = parsed_repo._replace(netloc=authenticated_netloc)
                authenticated_url = urlunparse(rebuilt)
                env_vars["GITHUB_TOKEN"] = team_config["token"]
                if team_config["base_url"]:
                    env_vars["GITHUB_ENTERPRISE_URL"] = team_config["base_url"]
                env_vars["GITREPO"] = authenticated_url
                print(f"[INFO] Constructed authenticated GITREPO URL for AI-SAST scan on {platform} using customer token.")
            elif platform == "gitlab":
                authenticated_netloc = f"oauth2:{team_config['token']}@{host_netloc}"
                rebuilt = parsed_repo._replace(netloc=authenticated_netloc)
                authenticated_url = urlunparse(rebuilt)
                env_vars["GITLAB_TOKEN"] = team_config["token"]
                if team_config["base_url"]:
                    env_vars["GITLAB_ENTERPRISE_URL"] = team_config["base_url"]
                env_vars["GITREPO"] = authenticated_url
                print(f"[INFO] Constructed authenticated GITREPO URL for AI-SAST scan on {platform} using customer token.")
            else:
                env_vars["GITREPO"] = repo_url

            # Core AI-SAST configuration from args
            env_vars["SCAN_HISTORY_BATCH_ID"] = str(batch_id)

            # Optional scan instance id (canonical naming only)
            if args_dict.get("scan-instance-id"):
                env_vars["SCAN_INSTANCE_ID"] = str(args_dict.get("scan-instance-id"))

            # HYBRID MODE: This Lambda is deployed in customer env, always uses hybrid mode
            print("[INFO] HYBRID MODE ENABLED - Using backend API endpoints instead of direct DB access")

            # Validate required hybrid mode env vars (passed from ai-sast-service)
            if not env_vars.get("AI_SAST_HYBRID_FINDINGS_ENDPOINT"):
                return {"statusCode": 500, "body": json.dumps({"error": "AI_SAST_HYBRID_FINDINGS_ENDPOINT not set in env for hybrid mode."})}
            if not env_vars.get("AI_SAST_HYBRID_UPLOAD_ENDPOINT"):
                return {"statusCode": 500, "body": json.dumps({"error": "AI_SAST_HYBRID_UPLOAD_ENDPOINT not set in env for hybrid mode."})}

            # Set hybrid mode flag
            env_vars["IS_HYBRID_MODE"] = "true"

            # DO NOT pass database credentials in hybrid mode
            # The scanner will fetch from and upload to backend API endpoints
            print("[INFO] HYBRID MODE: Skipping DB credentials - scanner will use backend API endpoints")

            # DO NOT pass cloud storage credentials in hybrid mode
            print("[INFO] HYBRID MODE: Skipping cloud storage credentials")

            # LLM API Keys - check env vars first (from ai-sast-service), then Lambda environment
            # In hybrid mode, customer's OpenAI deployment is used
            if not env_vars.get("OPENAI_API_KEY"):
                openai_api_key = os.environ.get("OPENAI_API_KEY")
                if openai_api_key:
                    env_vars["OPENAI_API_KEY"] = openai_api_key

            # HYBRID MODE: Support customer's private OpenAI deployment (including Azure OpenAI)
            # OPENAI_API_BASE: Custom endpoint URL (e.g., https://your-company.openai.azure.com/)
            # OPENAI_API_VERSION: API version for Azure OpenAI (e.g., 2024-02-15-preview)
            # OPENAI_API_TYPE: Set to "azure" for Azure OpenAI, otherwise standard OpenAI
            if not env_vars.get("OPENAI_API_BASE"):
                openai_api_base = os.environ.get("OPENAI_API_BASE")
                if openai_api_base:
                    env_vars["OPENAI_API_BASE"] = openai_api_base
                    print(f"[INFO] HYBRID MODE: Using custom OpenAI endpoint: {openai_api_base}")

            if not env_vars.get("OPENAI_API_VERSION"):
                openai_api_version = os.environ.get("OPENAI_API_VERSION")
                if openai_api_version:
                    env_vars["OPENAI_API_VERSION"] = openai_api_version

            if not env_vars.get("OPENAI_API_TYPE"):
                openai_api_type = os.environ.get("OPENAI_API_TYPE")
                if openai_api_type:
                    env_vars["OPENAI_API_TYPE"] = openai_api_type
                    print(f"[INFO] HYBRID MODE: OpenAI API type: {openai_api_type}")

            if not env_vars.get("GEMINI_API_KEY"):
                gemini_api_key = os.environ.get("GEMINI_API_KEY")
                if gemini_api_key:
                    env_vars["GEMINI_API_KEY"] = gemini_api_key

            # Backend notification URL (for notifying backend when scan completes)
            if not env_vars.get("AI_SAST_RESULT_URL"):
                env_vars["AI_SAST_RESULT_URL"] = os.environ.get("AI_SAST_RESULT_URL", "")

            # Ensure CLOUDDEFENSE_API_KEY is set (for authenticating with backend endpoints)
            if not env_vars.get("CLOUDDEFENSE_API_KEY"):
                env_vars["CLOUDDEFENSE_API_KEY"] = os.environ.get("CLOUDDEFENSE_API_KEY", "")

            # Build command-line to run the scanner entrypoint with hybrid flag
            args_list = ["python", "-m", "app.main", "--hybrid-mode"]

            if is_enterprise:
                args_list.append("--is-enterprise")

            # Log configuration (excluding sensitive values)
            safe_env_keys = [k for k in env_vars.keys() if 'KEY' not in k.upper() and 'PASSWORD' not in k.upper() and 'SECRET' not in k.upper() and 'TOKEN' not in k.upper()]
            print(f"[INFO] AI-SAST environment variables configured (non-sensitive): {safe_env_keys}")
            print(f"[INFO] AI-SAST command arguments: {args_list}")
            print("[INFO] Triggering AI-SAST EKS job (HYBRID MODE)...")

            trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list)
            print("[SUCCESS] AI-SAST job submission completed (HYBRID MODE).")
            return {"statusCode": 202, "body": json.dumps({"message": f"AI-SAST K8s job '{job_name}' accepted for processing (hybrid mode)."})}

        # ======================
        # Action: job_status_check
        # ======================
        elif action == "job_status_check":
            print("[INFO] Action: job_status_check")
            
            job_id = body.get("job-id")
            job_type = body.get("job-type", "hybrid")
            
            if not job_id:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing required parameter: 'job-id'"})}
            
            if job_type == "ai-sast":
                job_name_to_check = f"ai-sast-{job_id}"
            elif job_type == "public":
                job_name_to_check = f"cdefense-public-{job_id}"
            else:
                job_name_to_check = f"cdefense-hbyrid-{job_id}"
            
            print(f"[INFO] Checking status for job name: {job_name_to_check} (type: {job_type})")

            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps({"error": "EKS_CLUSTER_NAME environment variable not set."})}

            status_data = check_job_status(cluster_name, region, job_name_to_check)
            return {"statusCode": 200, "body": json.dumps(status_data)}

        # ======================
        # Invalid Action
        # ======================
        else:
            print(f"[ERROR] Invalid action received: {action}")
            return {"statusCode": 400, "body": json.dumps({"error": f"Invalid action: '{action}'"})}

    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"[EXCEPTION] An unexpected error occurred: {str(e)}")
        print("[TRACEBACK]", error_trace)
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "An internal server error occurred.",
                "details": str(e),
                "traceback": error_trace
            })
        }
