import requests
import logging

def authenticate_graph():
    tenant_id = "common"
    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft built-in client ID for device login
    authority_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    scopes = ["https://graph.microsoft.com/.default"]

    # Request device code
    response = requests.post(authority_url, data={"client_id": client_id, "scope": " ".join(scopes)})
    response.raise_for_status()
    device_code_data = response.json()

    print(f"To sign in, use a web browser to open {device_code_data['verification_uri']} and enter the code {device_code_data['user_code']} to authenticate.")

    # Poll for token
    while True:
        token_response = requests.post(token_url, data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                                        "client_id": client_id,
                                                        "device_code": device_code_data["device_code"]})
        token_data = token_response.json()

        if "access_token" in token_data:
            return token_data["access_token"]
        elif token_data.get("error") != "authorization_pending":
            logging.error("Authentication failed: " + token_data.get("error_description", "Unknown error"))
            raise Exception("Authentication failed. Check 'error_log.txt' for details.")
