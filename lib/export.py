import json
import csv
import logging
from pathlib import Path
from lib.fetch import fetch_entra_roles, fetch_user_details, fetch_group_details, fetch_group_members, fetch_conditional_access_policies
from lib.analyze import (
    count_excluded_admin_users,
    count_unique_exempt_users,
    count_exempt_users_with_specific_roles,
    count_unique_exempt_groups,
    count_exempt_groups_with_administrator_roles,
    count_exempt_groups_with_specific_roles
)
from lib.utils import print_color
from colorama import Fore

missing_policies = []  # Initialize the missing_policies list

def export_policies_to_csv(policies, csv_file):
    try:
        with open(csv_file, mode='w', newline='') as csvfile:
            fieldnames = [
                "id", "templateId", "displayName", "createdDateTime", "modifiedDateTime", "state",
                "conditions", "userRiskLevels", "signInRiskLevels", "clientAppTypes", "servicePrincipalRiskLevels",
                "insiderRiskLevels", "devices", "clientApplications", "authenticationFlows", "includeApplications",
                "excludeApplications", "includeUserActions", "includeAuthenticationContextClassReferences",
                "applicationFilter", "includeUsers", "excludeUsers", "includeGroups", "excludeGroups",
                "includeRoles", "excludeRoles", "includeGuestsOrExternalUsers", "excludeGuestsOrExternalUsers",
                "includePlatforms", "excludePlatforms", "includeLocations", "excludeLocations", "operator",
                "builtInControls", "customAuthenticationFactors", "termsOfUse", "authenticationStrength",
                "disableResilienceDefaults", "applicationEnforcedRestrictions", "cloudAppSecurity",
                "signInFrequency", "PersistentBrowser", "continuousAccessEvaluation", "secureSignInSession"
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for policy in policies:
                conditions = policy.get('conditions', {}) or {}
                grant_controls = policy.get('grantControls', {}) or {}
                session_controls = policy.get('sessionControls', {}) or {}
                applications = conditions.get('applications', {}) or {}
                users = conditions.get('users', {}) or {}
                platforms = conditions.get('platforms', {}) or {}
                locations = conditions.get('locations', {}) or {}

                csv_row = {
                    "id": policy.get('id', "none"),
                    "templateId": policy.get('templateId', "none"),
                    "displayName": policy.get('displayName', "none"),
                    "createdDateTime": policy.get('createdDateTime', "none"),
                    "modifiedDateTime": policy.get('modifiedDateTime', "none"),
                    "state": policy.get('state', "none"),
                    "conditions": json.dumps(conditions),
                    "userRiskLevels": conditions.get('userRiskLevels', []),
                    "signInRiskLevels": conditions.get('signInRiskLevels', []),
                    "clientAppTypes": conditions.get('clientAppTypes', []),
                    "servicePrincipalRiskLevels": conditions.get('servicePrincipalRiskLevels', []),
                    "insiderRiskLevels": conditions.get('insiderRiskLevels', []),
                    "devices": conditions.get('devices', {}),
                    "clientApplications": conditions.get('clientApplications', {}),
                    "authenticationFlows": conditions.get('authenticationFlows', {}),
                    "includeApplications": applications.get('includeApplications', []),
                    "excludeApplications": applications.get('excludeApplications', []),
                    "includeUserActions": applications.get('includeUserActions', []),
                    "includeAuthenticationContextClassReferences": applications.get('includeAuthenticationContextClassReferences', []),
                    "applicationFilter": applications.get('applicationFilter', {}),
                    "includeUsers": users.get('includeUsers', []),
                    "excludeUsers": users.get('excludeUsers', []),
                    "includeGroups": users.get('includeGroups', []),
                    "excludeGroups": users.get('excludeGroups', []),
                    "includeRoles": users.get('includeRoles', []),
                    "excludeRoles": users.get('excludeRoles', []),
                    "includeGuestsOrExternalUsers": users.get('includeGuestsOrExternalUsers', []),
                    "excludeGuestsOrExternalUsers": users.get('excludeGuestsOrExternalUsers', []),
                    "includePlatforms": platforms.get('includePlatforms', []),
                    "excludePlatforms": platforms.get('excludePlatforms', []),
                    "includeLocations": locations.get('includeLocations', []),
                    "excludeLocations": locations.get('excludeLocations', []),
                    "operator": grant_controls.get('operator', "none"),
                    "builtInControls": grant_controls.get('builtInControls', []),
                    "customAuthenticationFactors": grant_controls.get('customAuthenticationFactors', []),
                    "termsOfUse": grant_controls.get('termsOfUse', []),
                    "authenticationStrength": grant_controls.get('authenticationStrength', "none"),
                    "disableResilienceDefaults": session_controls.get('disableResilienceDefaults', "none"),
                    "applicationEnforcedRestrictions": session_controls.get('applicationEnforcedRestrictions', "none"),
                    "cloudAppSecurity": session_controls.get('cloudAppSecurity', "none"),
                    "signInFrequency": session_controls.get('signInFrequency', {}),
                    "PersistentBrowser": session_controls.get('persistentBrowser', {}),
                    "continuousAccessEvaluation": session_controls.get('continuousAccessEvaluation', {}),
                    "secureSignInSession": session_controls.get('secureSignInSession', {})
                }

                writer.writerow(csv_row)

        print_color(f"[+] Conditional access policies export successful: {csv_file}", Fore.GREEN)

    except Exception as e:
        logging.error(f"Error exporting policies to CSV: {e}")
        print("An error occurred during policy export to CSV. Check 'error_log.txt' for details.")

def export_policies(policies, directory, access_token):
    json_file = directory / "ConditionalAccessPolicies.json"
    csv_file = directory / "ConditionalAccessPolicies.csv"

    print_color("[*] Exporting conditional access policies...", Fore.CYAN)

    # Export policies to JSON
    try:
        with open(json_file, 'w') as file:
            json.dump(policies, file, indent=4)
        print_color(f"[+] Export successful: {json_file}", Fore.GREEN)
    except Exception as e:
        logging.error(f"Error exporting data to JSON: {e}")
        print_color("An error occurred during export. Check 'error_log.txt' for details.")

    # Export policies to CSV
    export_policies_to_csv(policies, csv_file)

    print_color("[*] Identifying excluded users, groups, roles, and other misconfigurations...", Fore.CYAN)
    excluded_users_list = []
    excluded_groups_list = []

    for policy in policies:
        try:
            conditions = policy.get('conditions', {}) or {}
            grant_controls = policy.get('grantControls', {}) or {}
            users = conditions.get('users', {}) or {}

            # Process excluded users
            excluded_user_ids = users.get('excludeUsers', [])
            for user_id in excluded_user_ids:
                user_details = fetch_user_details(user_id, access_token)
                excluded_users_list.append({
                    "exemptFromPolicy": policy.get('displayName', 'none'),
                    "grantType": ", ".join(grant_controls.get('builtInControls', [])),
                    "state": policy.get('state', 'none'),
                    "userDisplayName": user_details["displayName"],
                    "userPrincipalName": user_details["userPrincipalName"],
                    "objectId": user_id,
                    "groupMembership": ", ".join([group.replace("Member of group: ", "") for group in user_details["groupMembership"]]),
                    "entraIDRoleAssignment": ", ".join(user_details["entraIDRoleAssignment"])
                })

            # Process excluded groups
            excluded_group_ids = users.get('excludeGroups', [])
            for group_id in excluded_group_ids:
                group_details = fetch_group_details(group_id, access_token)
                excluded_groups_list.append({
                    "exemptFromPolicy": policy.get('displayName', 'none'),
                    "grantType": ", ".join(grant_controls.get('builtInControls', [])),
                    "state": policy.get('state', 'none'),
                    "groupName": group_details["groupName"],
                    "groupDescription": group_details["groupDescription"],
                    "objectId": group_id,
                    "entraIDRoleAssignment": ", ".join(group_details["entraIDRoleAssignment"]),
                    "totalDirectMembers": group_details["totalDirectMembers"],
                    "userCount": group_details["userCount"],
                    "groupCount": group_details["groupCount"],
                    "deviceCount": group_details["deviceCount"],
                    "otherCount": group_details["otherCount"]
                })

                # Fetch members of the group and append them to excluded_users_list
                group_members = fetch_group_members(group_id, access_token)
                for member in group_members:
                    user_details = fetch_user_details(member["userId"], access_token)

                    # Combine role assignments from both group and user
                    combined_roles = set(group_details["entraIDRoleAssignment"]) | set(user_details["entraIDRoleAssignment"])

                    excluded_users_list.append({
                        "exemptFromPolicy": policy.get('displayName', 'none'),
                        "grantType": ", ".join(grant_controls.get('builtInControls', [])),
                        "state": policy.get('state', 'none'),
                        "userDisplayName": user_details["displayName"],
                        "userPrincipalName": user_details["userPrincipalName"],
                        "objectId": member["userId"],
                        "groupMembership": group_details['groupName'],  # Direct group name without "Member of group:"
                        "entraIDRoleAssignment": ", ".join(combined_roles)
                    })

        except Exception as e:
            missing_policies.append(policy.get('id', 'Unknown ID'))
            logging.error(f"Error processing policy {policy.get('id', 'Unknown ID')}: {e}")
            print(f"Skipping problematic policy with ID {policy.get('id', 'Unknown ID')}. Check the logs for details.")

    # Export excluded users and groups
    export_excluded_users(excluded_users_list, directory)
    export_excluded_groups(excluded_groups_list, directory)
    
    print("\nResults")
    print("=" * 80)
    print("")
    # Count and print unique exempt users and role-specific metrics
    count_unique_exempt_users(excluded_users_list)
    count_excluded_admin_users(excluded_users_list)
    count_exempt_users_with_specific_roles(excluded_users_list)

    print("")
    # Count and print unique exempt groups and role-specific metrics
    count_unique_exempt_groups(excluded_groups_list)
    count_exempt_groups_with_administrator_roles(excluded_groups_list)
    count_exempt_groups_with_specific_roles(excluded_groups_list)

# Function to export excluded users to JSON and CSV
def export_excluded_users(excluded_users, directory):
    json_file = directory / "ExcludedUsers.json"
    csv_file = directory / "ExcludedUsers.csv"

    # Export to JSON
    try:
        with open(json_file, 'w') as file:
            json.dump(excluded_users, file, indent=4)
        print_color(f"[+] Excluded users export successful: {json_file}", Fore.GREEN)
    except Exception as e:
        logging.error(f"Error exporting excluded users to JSON: {e}")
        print("An error occurred during excluded users export to JSON. Check 'error_log.txt' for details.")

    # Export to CSV
    try:
        with open(csv_file, mode='w', newline='') as csvfile:
            fieldnames = ["exemptFromPolicy", "grantType", "state", "userDisplayName", "userPrincipalName", "objectId",
                          "groupMembership", "entraIDRoleAssignment"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(excluded_users)
        print_color(f"[+] Excluded users export successful: {csv_file}", Fore.GREEN)
    except Exception as e:
        logging.error(f"Error exporting excluded users to CSV: {e}")
        print("An error occurred during excluded users export to CSV. Check 'error_log.txt' for details.")

# Function to export excluded groups to JSON and CSV
def export_excluded_groups(excluded_groups, directory):
    json_file = directory / "ExcludedGroups.json"
    csv_file = directory / "ExcludedGroups.csv"

    # Export to JSON
    try:
        with open(json_file, 'w') as file:
            json.dump(excluded_groups, file, indent=4)
        print_color(f"[+] Excluded groups export successful: {json_file}", Fore.GREEN)
    except Exception as e:
        logging.error(f"Error exporting excluded groups to JSON: {e}")
        print("An error occurred during excluded groups export to JSON. Check 'error_log.txt' for details.")

    # Export to CSV
    try:
        with open(csv_file, mode='w', newline='') as csvfile:
            fieldnames = [
                "exemptFromPolicy", "grantType", "state", "groupName", "groupDescription",
                "objectId", "entraIDRoleAssignment", "totalDirectMembers", "userCount", "groupCount", "deviceCount", "otherCount"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(excluded_groups)
        print_color(f"[+] Excluded groups export successful: {csv_file}", Fore.GREEN)
    except Exception as e:
        logging.error(f"Error exporting excluded groups to CSV: {e}")
        print("An error occurred during excluded groups export to CSV. Check 'error_log.txt' for details.")
