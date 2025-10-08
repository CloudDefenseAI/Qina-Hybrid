# NOTE: RECOMMENDED APPROACH - Use AWS Secrets Manager instead of environment variables
# This is one approach and should be fine-tuned based on client requirements.

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


# --------------------
# GitHub API Helper
# --------------------
def get_github_api_base_url(is_enterprise):
    """
    Returns the appropriate GitHub API base URL based on the enterprise flag.
    """
    if is_enterprise:
        # Get enterprise URL from environment variables
        base_url = os.environ.get("GITHUB_ENTERPRISE_URL")
        if not base_url:
            raise ValueError("is_enterprise is true, but GITHUB_ENTERPRISE_URL environment variable is not set.")
        # Expecting a URL like https://your-ghe-instance.com/api/v3
        return base_url.rstrip('/')
    else:
        return "https://api.github.com"

# --------------------
# GitHub Repo Listing
# --------------------
def list_repositories(name, target_type, token, page=1, is_enterprise=False):
    """
    Fetches a list of repositories for a given GitHub user or organization,
    supporting both public and enterprise GitHub.
    """
    print(f"[INFO] Fetching GitHub repositories (Enterprise: {is_enterprise})...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    base_url = get_github_api_base_url(is_enterprise)
    
    if target_type == "user":
        repos_url = f"{base_url}/user/repos?type=all&per_page=100&page={page}"
    else:
        repos_url = f"{base_url}/orgs/{name}/repos?type=all&per_page=100&page={page}"
    # Debug line to confirm the final URL
    print(f"[DEBUG] Calling URL: {repos_url}")
    
    response = requests.get(repos_url, headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] GitHub API error ({response.status_code}): {response.text}")
        raise Exception(f"GitHub API error ({response.status_code}): {response.text}")

    has_next = 'rel="next"' in response.headers.get("Link", "")
    formatted_repos = []
    for repo in response.json():
        formatted_repos.append({
            "name": repo.get("full_name"),
            "cloneUrl": repo.get("clone_url"),
            "htmlUrl": repo.get("html_url"),
            "language": "Github",
            "private": repo.get("visibility") == "private"
        })

    print(f"[INFO] Retrieved {len(formatted_repos)} repositories")
    return {"content": formatted_repos, "hasNext": has_next}

# --------------------
# GitHub Branch Listing
# --------------------
def list_branches(repo_url, token, is_enterprise=False):
    """
    Fetches all branch names for a given GitHub repository URL,
    supporting both public and enterprise GitHub.
    """
    print(f"[INFO] Fetching branches for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Generic regex to extract owner/repo from public or enterprise URLs
    match = re.search(r"https://[^/]+/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitHub repository URL format.")

    owner, repo_name = match.groups()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"  # Changed for enterprise compatibility
    }
    
    base_url = get_github_api_base_url(is_enterprise)
    branches = []
    page = 1
    while True:
        branches_url = f"{base_url}/repos/{owner}/{repo_name}/branches?per_page=100&page={page}"
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
def get_default_branch(repo_url, token, is_enterprise=False):
    """
    Fetches the default branch for a given GitHub repository URL,
    supporting both public and enterprise GitHub.
    """
    print(f"[INFO] Fetching default branch for repo: {repo_url} (Enterprise: {is_enterprise})")

    # Generic regex to extract owner/repo from public or enterprise URLs
    match = re.search(r"https://[^/]+/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if not match:
        raise ValueError("Invalid GitHub repository URL format.")

    owner, repo_name = match.groups()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"  # Changed for enterprise compatibility
    }
    
    base_url = get_github_api_base_url(is_enterprise)
    repo_api_url = f"{base_url}/repos/{owner}/{repo_name}"
    response = requests.get(repo_api_url, headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] GitHub API error ({response.status_code}): {response.text}")
        raise Exception(f"GitHub API error ({response.status_code}): {response.text}")

    default_branch = response.json().get("default_branch")
    print(f"[INFO] Retrieved default branch: {default_branch}")
    return {"content": default_branch}


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
        print(f"[ERROR] Failed to generate EKS token for cluster '{cluster_name}'.")
        raise e

# --------------------
# EKS Job Launcher
# --------------------
def trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list, namespace="default"):
    """
    Configures and launches a job on the specified EKS cluster.
    """
    print(f"[INFO] Starting job creation for: {job_name}")
    eks = boto3.client('eks', region_name=region)
    cluster_info = eks.describe_cluster(name=cluster_name)['cluster']

    configuration = client.Configuration()
    configuration.host = cluster_info['endpoint']

    ca_data = cluster_info['certificateAuthority']['data']
    ca_path = '/tmp/ca.crt'
    with open(ca_path, 'w') as f:
        f.write(base64.b64decode(ca_data).decode())
    configuration.ssl_ca_cert = ca_path

    token = get_eks_token(cluster_name, region)
    configuration.api_key = {"authorization": f"Bearer {token}"}

    api_client = ApiClient(configuration=configuration)
    batch_v1 = client.BatchV1Api(api_client)

    print("[INFO] Defining Kubernetes job spec...")
    container = client.V1Container(
        name="scanner", image=image, args=args_list,
        env=[client.V1EnvVar(name=k, value=v) for k, v in env_vars.items()]
    )
    
    pod_spec = client.V1PodSpec(
        restart_policy="Never", containers=[container]
    )
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(name=job_name), spec=pod_spec
    )
    spec = client.V1JobSpec(
        template=template, backoff_limit=1, ttl_seconds_after_finished=30
    )
    job = client.V1Job(
        api_version="batch/v1", kind="Job",
        metadata=client.V1ObjectMeta(name=job_name), spec=spec
    )

    print("[INFO] Submitting job to Kubernetes cluster...")
    batch_v1.create_namespaced_job(namespace=namespace, body=job)
    print(f"[SUCCESS] Job '{job_name}' successfully created in namespace '{namespace}'.")

# --------------------
# EKS Job Status Checker (NEW)
# --------------------
def check_job_status(cluster_name, region, job_name, namespace="default"):
    """
    Checks the status and fetches logs for a given Kubernetes job.
    """
    print(f"[INFO] Checking status for job: {job_name}")
    eks = boto3.client('eks', region_name=region)
    try:
        cluster_info = eks.describe_cluster(name=cluster_name)['cluster']
    except eks.exceptions.ResourceNotFoundException:
        print(f"[ERROR] EKS cluster '{cluster_name}' not found.")
        raise ValueError(f"EKS cluster '{cluster_name}' not found.")

    configuration = client.Configuration()
    configuration.host = cluster_info['endpoint']
    ca_data = cluster_info['certificateAuthority']['data']
    ca_path = f'/tmp/{secrets.token_hex(8)}_ca.crt'
    with open(ca_path, 'w') as f:
        f.write(base64.b64decode(ca_data).decode())
    configuration.ssl_ca_cert = ca_path
    
    token = get_eks_token(cluster_name, region)
    configuration.api_key = {"authorization": f"Bearer {token}"}
    
    api_client = ApiClient(configuration=configuration)
    batch_v1 = client.BatchV1Api(api_client)
    core_v1 = client.CoreV1Api(api_client)

    try:
        job = batch_v1.read_namespaced_job(name=job_name, namespace=namespace)
        status = "SCHEDULED"
        logs = ""
        error_message = ""

        if job.status.succeeded:
            status = "SUCCEEDED"
        elif job.status.failed:
            status = "FAILED"
        
        if status != "SCHEDULED" or (job.status.active and job.status.active > 0):
            pod_label_selector = f"job-name={job_name}"
            pod_list = core_v1.list_namespaced_pod(namespace=namespace, label_selector=pod_label_selector)
            
            if pod_list.items:
                pod_name = pod_list.items[0].metadata.name
                try:
                    logs = core_v1.read_namespaced_pod_log(name=pod_name, namespace=namespace, container="scanner")
                    if status == "FAILED":
                        error_message = "Job failed. See logs for details."
                    elif status == "SUCCEEDED":
                        logs = f"successful job completed, logs: \n{logs}"
                except ApiException as e:
                    log_error_msg = f"Could not retrieve logs for pod {pod_name}: {e.reason}"
                    print(f"[ERROR] {log_error_msg}")
                    logs = log_error_msg
                    if status == "FAILED":
                        error_message = log_error_msg
            else:
                logs = "Pod not found or not ready. Logs are not yet available."
                if status == "FAILED":
                    error_message = "Job failed, but its pod could not be found to retrieve logs."
        
        return {"status": status, "logs": logs, "error": error_message}

    except ApiException as e:
        if e.status == 404:
            print(f"[ERROR] Job '{job_name}' not found in namespace '{namespace}'.")
            return {"status": "NOT_FOUND", "logs": "", "error": f"Job '{job_name}' not found."}
        else:
            print(f"[ERROR] Kubernetes API error: {e}")
            raise e

# --------------------
# Lambda Handler
# --------------------
def lambda_handler(event, context):
    """
    Main handler for the Lambda function. Routes actions for listing repositories,
    branches, or triggering scans.
    """
    print("[INFO] Lambda triggered with event:")
    

    if "body" in event and isinstance(event["body"], str):
        try:
            event = json.loads(event["body"])
            print("[INFO] Parsed request body from Function URL.")
        except Exception as parse_err:
            print(f"[ERROR] Failed to parse 'body': {parse_err}")
            return {"statusCode": 400, "body": json.dumps("Invalid request body")}

    action = event.get("action")
    github_token = os.environ.get("GITHUB_TOKEN")

    if not github_token:
        error_msg = "FATAL: GITHUB_TOKEN environment variable not set."
        print(f"[ERROR] {error_msg}")
        return {"statusCode": 500, "body": json.dumps(error_msg)}

    try:
        if action == "list_repos":
            print("[INFO] Action: list_repos")
            name = os.environ.get("GITHUB_USERNAME")
            target_type = event.get("type", "user")
            page = int(event.get("page", 1))
            is_enterprise = str(event.get("is-enterprise", "false")).lower() == "true" # Corrected key

            if not name:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter: 'name'")}
            if target_type not in ["user", "org"]:
                return {"statusCode": 400, "body": json.dumps("Invalid 'type'. Must be 'user' or 'org'.")}

            repos_data = list_repositories(name, target_type, github_token, page, is_enterprise=is_enterprise)
            return {"statusCode": 200, "body": json.dumps(repos_data)}

        elif action == "list_branches":
            print("[INFO] Action: list_branches")
            repo_url = event.get("repo_url")
            repo_type = event.get("type")
            is_enterprise = str(event.get("is-enterprise", "false")).lower() == "true" # Corrected key

            if not repo_url:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter: 'repo_url'")}
            if repo_type != "GITHUB":
                return {"statusCode": 400, "body": json.dumps("Invalid 'type'. Must be 'GITHUB'.")}

            branch_data = list_branches(repo_url, github_token, is_enterprise=is_enterprise)
            return {"statusCode": 200, "body": json.dumps(branch_data)}

        elif action == "default_branch":
            print("[INFO] Action: default_branch")
            repo_url = event.get("repo_url")
            repo_type = event.get("type")
            is_enterprise = str(event.get("is-enterprise", "false")).lower() == "true" # Corrected key

            if not repo_url:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter: 'repo_url'")}
            if repo_type != "GITHUB":
                return {"statusCode": 400, "body": json.dumps("Invalid 'type'. Must be 'GITHUB'.")}

            default_branch_data = get_default_branch(repo_url, github_token, is_enterprise=is_enterprise)
            return {"statusCode": 200, "body": json.dumps(default_branch_data)}

        elif action == "trigger_scan":
            print("[INFO] Action: trigger_scan")
            
            args_dict = event.get("args", {})
            if not args_dict:
                return {"statusCode": 400, "body": json.dumps("Job arguments ('args') dictionary cannot be empty.")}
            
            # Get job-id from the nested 'args' dictionary.
            job_id = args_dict.get("job-id")
            if not job_id:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter 'job-id' in 'args'.")}

            # Construct the job name using the client-provided job-id.
            job_name = f"cdefense-hbyrid-{job_id}"
            print(f"[INFO] Constructed job name from client-provided id: {job_name}")

            image = os.environ.get("CLI_IMAGE")
            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps("EKS_CLUSTER_NAME environment variable not set.")}

            env_vars = event.get("env", {})
            
            if args_dict.get("repo-type") in ["GITHUB", "BRANCH"]:
                repo_url = args_dict.get("repo-url")
                if repo_url:
                    url_without_scheme = repo_url.replace("https://", "").replace("http://", "")
                    authenticated_url = f"https://{github_token}@{url_without_scheme}"
                    env_vars["GIT_REPO"] = authenticated_url
                    print("[INFO] Constructed authenticated GIT_REPO URL for private repository.")

            env_vars["GITHUB_TOKEN"] = github_token
            env_vars["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID_HYBRID")
            env_vars["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY_HYBRID")
            env_vars["BUCKET_NAME"] = os.environ.get("BUCKET_NAME_HYBRID")
            env_vars["AWS_REGION"] = os.environ.get("AWS_REGION_HYBRID")

            args_list = ["full"]
            
            if str(args_dict.pop("is-enterprise", "false")).lower() == "true": # Corrected key
                args_list.append("--is-enterprise")
            
            for key, value in args_dict.items():
                args_list.append(f"--{key}={str(value)}")

            print(f"[INFO] Constructed job arguments: {args_list}")
            print("[INFO] Triggering EKS job...")
            trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list)
            print("[SUCCESS] Job submission process completed.")
            return {"statusCode": 202, "body": json.dumps(f"K8s job '{job_name}' accepted for processing.")}

        elif action == "trigger_scan_public":
            print("[INFO] Action: trigger_scan_public")
            
            args_dict = event.get("args", {})
            if not args_dict:
                return {"statusCode": 400, "body": json.dumps("Job arguments ('args') dictionary cannot be empty.")}
            
            # Get job-id from the nested 'args' dictionary.
            job_id = args_dict.get("job-id")
            if not job_id:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter 'job-id' in 'args'.")}

            # Validate repo-url is provided for public repo scan
            repo_url = args_dict.get("repo-url")
            if not repo_url:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter 'repo-url' for public repository scan.")}

            # Construct the job name using the client-provided job-id.
            job_name = f"cdefense-public-{job_id}"
            print(f"[INFO] Constructed job name for public repo scan: {job_name}")

            image = os.environ.get("CLI_IMAGE")
            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps("EKS_CLUSTER_NAME environment variable not set.")}

            # Set up environment variables for public repo scan
            env_vars = event.get("env", {})
            
            # For public repositories, we can use the URL directly without authentication
            env_vars["GIT_REPO"] = repo_url
            print(f"[INFO] Using public repository URL: {repo_url}")

            # Add AWS credentials for results storage
            env_vars["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID_HYBRID")
            env_vars["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY_HYBRID")
            env_vars["BUCKET_NAME"] = os.environ.get("BUCKET_NAME_HYBRID")
            env_vars["AWS_REGION"] = os.environ.get("AWS_REGION_HYBRID")

            
            

            args_list = ["full"]
            
            # Handle enterprise flag if present
            if str(args_dict.pop("is-enterprise", "false")).lower() == "true":
                args_list.append("--is-enterprise")
            
            # Add all other arguments
            for key, value in args_dict.items():
                args_list.append(f"--{key}={str(value)}")

            print(f"[INFO] Constructed job arguments for public repo: {args_list}")
            print("[INFO] Triggering EKS job for public repository scan...")
            trigger_eks_job(cluster_name, region, job_name, image, env_vars, args_list)
            print("[SUCCESS] Public repository scan job submission completed.")
            return {"statusCode": 202, "body": json.dumps(f"K8s job '{job_name}' accepted for processing.")}

        elif action == "job_status_check":
            print("[INFO] Action: job_status_check")
            job_id = event.get("job-id")
            job_type = event.get("job-type", "hybrid")  # Default to hybrid for backward compatibility
            
            if not job_id:
                return {"statusCode": 400, "body": json.dumps("Missing required parameter: 'job-id'")}
            
            # Construct the full job name to check based on job type
            if job_type == "public":
                job_name_to_check = f"cdefense-public-{job_id}"
            else:
                job_name_to_check = f"cdefense-hbyrid-{job_id}"  # Keep the original spelling for backward compatibility
            
            print(f"[INFO] Checking status for job name: {job_name_to_check} (type: {job_type})")

            cluster_name = os.environ.get("EKS_CLUSTER_NAME")
            region = os.environ.get("AWS_REGION")

            if not cluster_name:
                return {"statusCode": 500, "body": json.dumps("EKS_CLUSTER_NAME environment variable not set.")}

            status_data = check_job_status(cluster_name, region, job_name_to_check)
            return {"statusCode": 200, "body": json.dumps(status_data)}

        else:
            print(f"[ERROR] Invalid action received: {action}")
            return {"statusCode": 400, "body": json.dumps("Invalid or missing 'action'.")}

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
