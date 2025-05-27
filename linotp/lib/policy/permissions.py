from typing import Dict, List

from linotp.lib.policy.evaluate import PolicyEvaluator
from linotp.lib.policy.util import get_policies
from linotp.lib.realm import getRealms
from linotp.lib.user import User

from .definitions import get_policy_definitions

REALMED_POLICY_SCOPES = ["admin", "getToken", "reporting.access"]
GLOBAL_POLICY_SCOPES = [
    "audit",
    "monitoring",
    "system",
    "tools",
]


class UserPermissions(dict):
    """
    Dict to represent the Permissions of a given User.

    A Permission is defined by a scope and an action of that
    scope the User is allowed to perform.

    Has keys `inRealm`, `anyRealm`, `global`.
      - value of `inRealm`: {realm:PermissionDict for realm in all_realms}
      - value of `anyRealm`: PermissionDict with Permissions that are allowed
        for the User on any realm.
        This includes Permissions granted through Policies on realm "*" and implies
        that a user has e.g. Permissions on a Token without realm.
      - value of `global`: PermissionDict with Permissions that are allowed
        for the User and not bound to a realm. E.g. "audit/view".

    example for PermissionDict:
        {
            "scope_1": ["action_1", "action_2"],
            "scope_2": ["action_5"],
        }
    """

    def __init__(self, user: User) -> None:
        self._user = user
        self._policy_eval = PolicyEvaluator(get_policies())
        self._all_realms = [realm["realmname"] for realm in getRealms().values()]
        _empty_permissions = {
            "inRealm": {realm: {} for realm in self._all_realms},
            "anyRealm": {},
            "global": {},
        }
        super().__init__(_empty_permissions)
        self._update_user_permissions()

    @property
    def _relevant_policies(self):
        policy_definitions = get_policy_definitions()
        return {
            scope: action
            for scope, action in policy_definitions.items()
            if scope in (REALMED_POLICY_SCOPES + GLOBAL_POLICY_SCOPES)
        }

    def _update_user_permissions(self):
        for scope, actions in self._relevant_policies.items():
            if not self._policy_eval.has_policy({"scope": scope, "active": True}):
                # no policies -> user has permission for all actions in realm for specific scope
                self._extend_permissions(scope, list(actions), ["*"])
                continue

            for action in actions:
                allowed_realms = self._get_realms_for_permission(scope, action)
                self._extend_permissions(scope, [action], allowed_realms)

    def _extend_permissions(
        self,
        scope: str,
        actions: List[str] = [],
        realms_to_extend: List[str] = [],
    ):
        """adds actions to relevant PermissionDict

        Args:
            scope (str):
                the scope to add actions on
            actions (List[str], optional):
                actions of `scope` to add.
                If no actions are provided,all actions of `scope` are added.
                Defaults to [].
            realms_to_extend (List[str], optional):
                Realms the permission should be added to.
                If `*` in `realms`, permissions are added to all realms and `anyRealm`.
                Defaults to [].
        """
        if not realms_to_extend:
            return

        if scope in REALMED_POLICY_SCOPES:
            if scope == "admin":
                # the 'allowed to list the tokens' / 'admin/show' permission:
                # the admin/show permission is an implicit permission by the means
                # that an admin is allowed to list the tokens for any realm he is
                # allowed to access via policies where any action is defined.
                actions.append("show")

            if "*" in realms_to_extend:
                updated_permissions = self["anyRealm"].get(scope, []) + actions
                self["anyRealm"][scope] = list(set(updated_permissions))
                # extend permission of all realms
                realms_to_extend = self._all_realms

            for realm in realms_to_extend:
                updated_permissions = self["inRealm"][realm].get(scope, []) + actions
                self["inRealm"][realm][scope] = list(set(updated_permissions))
        elif scope in GLOBAL_POLICY_SCOPES:
            # user has gobal permission if at least one policy allows it
            updated_permissions = self["global"].get(scope, []) + actions
            self["global"][scope] = updated_permissions

    def _get_realms_for_permission(self, scope, action):
        def policy_active_for_realm(realm: str):
            # Note: This takes advantage of local variable scope
            policies = self._policy_eval.has_policy(
                {
                    "realm": realm,
                    "scope": scope,
                    "action": action,
                    "user": self._user,
                    "active": True,
                },
                strict_matches=False,
            )
            return len(policies) > 0

        if policy_active_for_realm("*"):
            allowed_realms = ["*"]
            return allowed_realms

        allowed_realms = [
            realm for realm in self._all_realms if policy_active_for_realm(realm)
        ]
        return allowed_realms

    def parse_for_context_api(self):
        """parsed permissions for manage/context api

        Returns:
            example: {
                "inRealm": {
                    "realm_1": ["admin/show"]
                    "realm_2": ["audit/show", "audit/reset"]
                },
                "anyRealm": ["audit/show"],
                "global": ["audit/view"]
            }
        """

        def _parse_scopes(scopes: List[Dict]):
            parsed_permissions = []
            for scope, actions in scopes.items():
                permissions = [f"{scope}/{action}" for action in actions]
                parsed_permissions.extend(permissions)
            return parsed_permissions

        result = {
            "inRealm": {
                realm: _parse_scopes(scopes)
                for realm, scopes in self["inRealm"].items()
            },
            "anyRealm": _parse_scopes(self["anyRealm"]),
            "global": _parse_scopes(self["global"]),
        }
        return result
