package rbac.authz

# user-role assignments per organization
user_roles := {
    "alice": [{"org_id": 1, "roles": ["owner", "admin"]}],
    "bob": [{"org_id": 1, "roles": ["driver"]}, {"org_id": 2, "roles": ["owner"]}],
    "larry": [{"org_id": 1, "roles": ["laborer"]}]
}

# role-permissions assignments
role_permissions := {
    "owner": [{"action": "read",  "object": "billing_methods"},
              {"action": "write",  "object": "billing_methods"},
              {"action": "read",  "object": "driver_assignments"},
              {"action": "write",  "object": "driver_assignments"}],
    "admin": [{"action": "read",  "object": "driver_assignments"},
               {"action": "write",  "object": "driver_assignments"},
               {"action": "read",  "object": "vehicle_issues"}],
    "driver": [{"action": "read",  "object": "driver_assignments"}],
    "laborer": [{"action": "write",  "object": "vehicle_issues"},
                {"action": "read",  "object": "vehicle_issues"}]
}

# logic that implements RBAC.
default allow = false
allow {
    # lookup the list of roles for the user
    roles := user_roles[input.user]

    # for each role in that list that matches the org id in question
    r := [rs | roles[i].org_id == input.org_id; rs := roles[i].roles][0][_]

    # lookup the permissions list for role r
    permissions := role_permissions[r]

    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
}