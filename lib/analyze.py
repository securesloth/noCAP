import logging
from lib.utils import print_orange

# Constants for critical roles
CRITICAL_ROLES = {
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Privileged Authentication Administrator": "7be44c8a-adaf-4e2a-b7b3-44f9f9c88245",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Application Administrator": "9c094953-4995-41c8-8b54-4f680a8ee4c8",
    "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7"
}

def check_incomplete_client_app_types(policies):
    expected_client_apps = {"exchangeActiveSync", "browser", "mobileAppsAndDesktopClients", "other"}
    policies_with_issues = []

    for policy in policies:
        client_app_types = set(policy.get("conditions", {}).get("clientAppTypes", []))

        if client_app_types not in [{"all"}, expected_client_apps]:
            policies_with_issues.append(policy.get("displayName", "Unknown Policy"))

    if policies_with_issues:
        print_orange(f"\nIdentified {len(policies_with_issues)} unique policies where not all client app types are included (note that this may be by design)!")
        print_orange(f"Policies with incomplete client app coverage:")
        for policy_name in policies_with_issues:
            print_orange(f"-> {policy_name}")

def check_office365_contradiction(policies):
    office_365_app_ids = {
        '00000002-0000-0ff1-ce00-000000000000',  # Microsoft Office
        '2f3f02c9-5679-4a5c-a605-0de55b07d135',  # Office 365 SharePoint Online
        '00000003-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online
    }

    conflicting_policies = []

    for policy in policies:
        include_app_ids = set(policy.get('conditions', {}).get('applications', {}).get('includeApplications', []))
        exclude_apps = set(policy.get('conditions', {}).get('applications', {}).get('excludeApplications', []))

        # Check for Office 365 app contradiction
        if include_app_ids & office_365_app_ids and "Office365" in exclude_apps:
            conflicting_policies.append(policy.get('displayName', 'Unknown Policy'))

    # Print the results if any contradictions are found
    if conflicting_policies:
        print_orange(f"\nIdentified {len(conflicting_policies)} policies that include individual Office 365 apps but exclude Office 365 as a whole; this cancels out the policy!")
        print_orange(f"Policies with Office 365 contradictions:")
        for policy_name in conflicting_policies:
            print_orange(f"-> {policy_name}")

def check_excluded_roles(policies):
    # Role IDs for specific roles we are checking
    critical_roles = {
        "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
        "Privileged Authentication Administrator": "7be44c8a-adaf-4e2a-b7b3-44f9f9c88245",
        "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "Application Administrator": "9c094953-4995-41c8-8b54-4f680a8ee4c8",
        "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7"
    }

    policies_with_excluded_roles = []  # Tracks policies with any excluded role
    policies_with_critical_roles = []  # Tracks policies excluding critical roles

    for policy in policies:
        excluded_roles = policy.get("conditions", {}).get("users", {}).get("excludeRoles", [])
        policy_name = policy.get("displayName", "Unknown Policy")

        if excluded_roles:
            policies_with_excluded_roles.append(policy_name)

        # Check if any critical roles are excluded
        if any(role_id in excluded_roles for role_id in critical_roles.values()):
            policies_with_critical_roles.append(policy_name)

    # Print summary
    print_orange(f"\nIdentified {len(policies_with_excluded_roles)} unique policies where Entra ID roles are excluded!")
    print_orange(f"Identified {len(policies_with_critical_roles)} unique policies where the Privileged Auth Admin, Privileged Role Admin, App Admin, or Cloud App Admin roles are excluded!")

    if policies_with_critical_roles:
        print_orange(f"Policies where the Privileged Auth Admin, Privileged Role Admin, App Admin, or Cloud App Admin roles are excluded:")
        for policy in policies_with_critical_roles:
            print_orange(f"-> {policy}")

def count_excluded_admin_users(excluded_users):
    # Create a set to store unique user IDs with administrator roles
    unique_admin_users = set(
        user["objectId"] for user in excluded_users if any("administrator" in role.lower() for role in user["entraIDRoleAssignment"].split(", "))
    )
    
    # Count the unique users
    admin_count = len(unique_admin_users)
    print_orange(f"• Identified {admin_count} unique CAP-exempt users with an Entra ID administrator role assigned!")

def count_unique_exempt_users(excluded_users):
    unique_users = {user["objectId"] for user in excluded_users}
    print_orange(f"Total unique CAP-exempt Users: {len(unique_users)}")

def count_exempt_users_with_specific_roles(excluded_users):
    roles_of_interest = {"global administrator", "privileged authentication administrator", "privileged role administrator",
                         "application administrator", "cloud application administrator"}
    unique_users_with_roles = {
        user["objectId"] for user in excluded_users if any(
            role.lower() in roles_of_interest for role in user["entraIDRoleAssignment"].split(", "))
    }
    print_orange(f"• Identified {len(unique_users_with_roles)} unique CAP-exempt users with Global Admin, "
          f"Privileged Auth Admin, Privileged Role Admin, App Admin, or Cloud App Admin role assigned!")

def count_unique_exempt_groups(excluded_groups):
    unique_groups = {group["objectId"] for group in excluded_groups}
    print_orange(f"Total unique CAP-exempt groups: {len(unique_groups)}")

def count_exempt_groups_with_administrator_roles(excluded_groups):
    unique_admin_groups = {
        group["objectId"] for group in excluded_groups if any("administrator" in role.lower() for role in group["entraIDRoleAssignment"].split(", "))
    }
    print_orange(f"• Identified {len(unique_admin_groups)} unique CAP-exempt groups with an Entra ID administrator role assigned!")

def count_exempt_groups_with_specific_roles(excluded_groups):
    roles_of_interest = {"global administrator", "privileged authentication administrator", "privileged role administrator",
                         "application administrator", "cloud application administrator"}
    unique_groups_with_roles = {
        group["objectId"] for group in excluded_groups if any(
            role.lower() in roles_of_interest for role in group["entraIDRoleAssignment"].split(", "))
    }
    print_orange(f"• Identified {len(unique_groups_with_roles)} unique CAP-exempt groups with Global Admin, "
          f"Privileged Auth Admin, Privileged Role Admin, App Admin, or Cloud App Admin role assigned!")
    
def analyze_policies(policies):
    """Combined analysis function for policies"""
    # Check for incomplete client apps
    incomplete_apps = check_incomplete_client_app_types(policies)
    if incomplete_apps:
        print_orange(f"\nFound {len(incomplete_apps)} policies with incomplete client app types")
        
    # Check for Office 365 contradictions
    contradictions = check_office365_contradiction(policies)
    if contradictions:
        print_orange(f"\nFound {len(contradictions)} policies with Office 365 contradictions")
        
    # Check for excluded roles
    role_issues = check_excluded_roles(policies)
    if role_issues:
        print_orange(f"\nFound {len(role_issues)} policies with role exclusion issues")



