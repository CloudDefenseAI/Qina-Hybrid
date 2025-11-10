# 🔑 Guide to Creating a GitLab Personal Access Token
A Personal Access Token is used to authenticate with the GitLab API and can also be used to authenticate with Git over HTTP, particularly when Two-Factor Authentication (2FA) is enabled.

## Step 1: Access the Personal Access Tokens Section
1. Log in to your GitLab account.
2. In the left-hand sidebar, navigate to your **User Settings**.
3. Click on **Personal access tokens**.

## Step 2: Start the Token Creation Process
On the "Personal access tokens" page, click the **Add new token** button, typically found in the top-right corner.

## Step 3: Configure the Token Details
Fill in the required details for your new token:

- **Token name**: Enter a descriptive name for your token (e.g., `qina-hybrid-scanner`).
- **Description** (optional): Add a brief description if needed.
- **Expiration date**: Set an expiration date. An administrator may enforce a maximum token lifetime.
- **Select scopes**: Choose the permissions the token will have. The scopes define the actions the token can perform.
  - For cloning private projects, check the **`read_repository`** scope.
  - You may also need **`read_api`** if the integration requires access to the GitLab API (e.g., to list projects or groups).
  > **Note**: For security, always grant only the minimum required scopes.

## Step 4: Create the Token
After configuring the name, expiration, and scopes, click the **Create personal access token** button at the bottom of the page.

## Step 5: Save Your Token
**Crucial**: Once created, GitLab will only display the token value **once**. Make sure to copy and securely store the token value immediately. If you lose it, you will have to revoke the token and create a new one.
