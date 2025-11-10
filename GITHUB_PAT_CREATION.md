# Integrating via Personal Access Token (PAT)
This method requires generating a scoped Personal Access Token directly within GitHub and then providing that token to the security platform.

## Part A: Generating the Personal Access Token (PAT) on GitHub
The token must be generated with the correct scopes to ensure repository access.

### 1. Navigate to Developer Settings
1. In GitHub, go to your user **Settings** (click your profile picture in the top-right corner).
2. In the left sidebar, scroll down and click on **Developer settings**.

### 2. Start Token Generation
1. In the Developer settings menu, select **Personal access tokens** and then **Tokens (classic)**.
2. Click the **Generate new token** dropdown, and then choose **Generate new token (classic)**.

### 3. Configure Token Details and Scopes (CRITICAL)
On the "New personal access token" page:
- **Note**: Provide a clear, descriptive name for the token (e.g., `qina-hybrid-scanner`).
- **Expiration**: Set an appropriate expiration date (e.g., 90 days is recommended).
- **Select Scopes**: Under the "Select scopes" section, you **must** check the main `repo` checkbox.
  > **Note**: Checking the top-level `repo` scope grants the necessary permissions to clone and analyze private repositories.

### 4. Finalize and Copy the Token
1. Scroll to the bottom and click **Generate token**.
2. **IMPORTANT**: Copy the generated token immediately and store it in a safe place. You will **not** be able to view it again after you navigate away from the page.
