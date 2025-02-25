# lib/fetch.py
import requests
from functools import wraps
import time
import logging
from .utils import GRAPH_API_VERSION

def retry_on_failure(max_retries=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        logging.error(f"Failed after {max_retries} attempts: {e}")
                        raise
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

@retry_on_failure()
def fetch_conditional_access_policies(access_token):
    # Existing fetch logic with better error handling
    pass

def fetch_current_user(access_token):
    """Fetch details of the currently authenticated user"""
    headers = {'Authorization': f'Bearer {access_token}'}
    url = "https://graph.microsoft.com/v1.0/me"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        user_data = response.json()
        return user_data.get('userPrincipalName', 'Unknown User')
    except Exception as e:
        logging.error(f"Error fetching current user: {e}")
        return "Unknown User"

def fetch_entra_roles(object_id, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    role_assignments_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{object_id}'"
    role_definitions_url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"

    role_assignments = []
    role_definitions = {}

    try:
        response = requests.get(role_definitions_url, headers=headers)
        if response.status_code == 200:
            roles = response.json().get("value", [])
            for role in roles:
                role_definitions[role["id"]] = role.get("displayName", "Unknown Role")
    except Exception as e:
        logging.error(f"Error fetching role definitions: {e}")
        return ["Error fetching roles"]

    try:
        response = requests.get(role_assignments_url, headers=headers)
        if response.status_code == 200:
            assignments = response.json().get("value", [])
            for assignment in assignments:
                role_id = assignment.get("roleDefinitionId")
                role_name = role_definitions.get(role_id, "Unknown Role")
                role_assignments.append(role_name)
    except Exception as e:
        logging.error(f"Error fetching role assignments for object {object_id}: {e}")
        return ["Error fetching assignments"]

    return role_assignments

def fetch_user_details(user_id, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}

    user_info_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    group_membership_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"

    user_details = {
        "displayName": "none",
        "userPrincipalName": "none",
        "groupMembership": [],
        "entraIDRoleAssignment": []
    }

    try:
        response = requests.get(user_info_url, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            user_details["displayName"] = user_data.get("displayName", "none")
            user_details["userPrincipalName"] = user_data.get("userPrincipalName", "none")
    except Exception as e:
        logging.error(f"Error fetching user info for {user_id}: {e}")

    try:
        response = requests.get(group_membership_url, headers=headers)
        if response.status_code == 200:
            groups = response.json().get("value", [])
            user_details["groupMembership"] = [group.get("displayName", "unknown group") 
                                               for group in groups if group.get("@odata.type") == "#microsoft.graph.group"]
    except Exception as e:
        logging.error(f"Error fetching group membership for {user_id}: {e}")

    user_details["entraIDRoleAssignment"] = fetch_entra_roles(user_id, access_token)
    return user_details

def fetch_group_details(group_id, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    group_info_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}"
    group_members_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"

    group_details = {
        "groupName": "none",
        "groupDescription": "none",
        "objectId": group_id,
        "entraIDRoleAssignment": fetch_entra_roles(group_id, access_token),
        "totalDirectMembers": 0,
        "userCount": 0,
        "groupCount": 0,
        "deviceCount": 0,
        "otherCount": 0
    }

     # Fetch group metadata
    try:
        response = requests.get(group_info_url, headers=headers)
        if response.status_code == 200:
            group_data = response.json()
            group_details["groupName"] = group_data.get("displayName", "none")
            group_details["groupDescription"] = group_data.get("description", "none")

    except Exception as e:
        logging.error(f"Error fetching group info for {group_id}: {e}")

    # Fetch group members and count categories
    try:
        response = requests.get(group_members_url, headers=headers)
        if response.status_code == 200:
            members = response.json().get('value', [])
            group_details["totalDirectMembers"] = len(members)

            # Categorize members
            for member in members:
                member_type = member.get("@odata.type", "").lower()
                if "user" in member_type:
                    group_details["userCount"] += 1
                elif "group" in member_type:
                    group_details["groupCount"] += 1
                elif "device" in member_type:
                    group_details["deviceCount"] += 1
                else:
                    group_details["otherCount"] += 1
    except Exception as e:
        logging.error(f"Error fetching group members for {group_id}: {e}")

    return group_details

def fetch_group_members(group_id, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    group_members_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"

    group_members = []
    try:
        response = requests.get(group_members_url, headers=headers)
        response.raise_for_status()
        members = response.json().get('value', [])
        for member in members:
            if member.get('@odata.type') == "#microsoft.graph.user":
                group_members.append({
                    "userId": member.get("id"),
                    "displayName": member.get("displayName", "none"),
                    "userPrincipalName": member.get("userPrincipalName", "none")
                })
    except Exception as e:
        logging.error(f"Error fetching group members for group {group_id}: {e}")
    return group_members

def fetch_conditional_access_policies(access_token):
    endpoints = ["https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                 "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"]
    all_policies = {}

    headers = {'Authorization': f'Bearer {access_token}'}

    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            policies = response.json().get('value', [])
            for policy in policies:
                policy_id = policy.get('id', 'unknown')
                if policy_id not in all_policies:
                    all_policies[policy_id] = policy
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching conditional access policies from {endpoint}: {e}")
            print(f"An error occurred while accessing {endpoint}. Check 'error_log.txt' for details.")

    return list(all_policies.values())
