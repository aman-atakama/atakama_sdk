"""Atakama keyserver ruleset library"""
import abc
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Union, TYPE_CHECKING, Optional, Any
import logging

import yaml

from atakama import Plugin

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)


class RequestType(Enum):
    DECRYPT = "decrypt"
    SEARCH = "search"
    CREATE_PROFILE = "create_profile"
    ACTIVATE_LOCATION = "activate_location"
    CREATE_LOCATION = "create_location"
    RENAME_FILE = "rename"
    SECURE_EXPORT = "secure_export"


@dataclass
class ProfileInfo:
    profile_id: bytes
    """Requesting profile uuid"""
    profile_words: List[str]
    """Requesting profile 'words' mnemonic"""


@dataclass
class MetaInfo:
    meta: str
    """Typically the full mount-path of a file."""
    complete: bool
    """Whether the meta is complete (fully verified) or partial (missing components)"""


@dataclass
class ApprovalRequest:
    request_type: RequestType
    """Request type"""
    device_id: bytes
    """Requesting device uuid"""
    profile: ProfileInfo
    """"""
    auth_meta: List[MetaInfo]
    """Authenticated metadata associated with the encrypted data.   Typically a path to a file."""


class RulePlugin(Plugin):
    """
    Base class for key server approval rule handlers.

    When a key server receives a request, rules are consulted for approval.

    Each rule receives its configuration from the policy file,
    not the atakama config, like other plugins.

    In addition to standard arguments from the policy, file a unique
    `rule_id` is injected, if not present.
    """

    @abc.abstractmethod
    def approve_request(self, request: ApprovalRequest) -> Optional[bool]:
        """
        Return True if the request to decrypt a file will be authorized.

        Return False if the request is to be denied.
        Raise None if the request type is unknown or invalid.
        Exceptions and None are logged, and considered False.

        This is called any time:
            a decryption agent wishes to decrypt a file.
            a decryption agent wishes to search a file.
            a decryption agent wishes to perform other multifactor request types.

        See the RequestType class for more information.
        """

    def check_quota(self, profile: ProfileInfo) -> bool:
        """
        Returns False if the profile will not be approved in the next request.
        Returns True if the profile *may* be approved for access, and is not past a limit.

        This is not a guarantee of future approval, it's a way of checking to see if any users have
        reached any limits, quotas or other stateful things for reporting purposed.
        """

    def clear_quota(self, profile: ProfileInfo) -> None:
        """
        Reset or clear any limits, quotas, access counts, bytes-transferred for a given profile.

        Used by an administrator to "clear" or "reset" a user that has hit limits.
        """

    @classmethod
    def from_dict(cls, data: dict) -> "RulePlugin":
        """
        Factory function called with a dict from the rules yaml file.
        """

        assert type(data) is dict, "Rule entries must be dicts"
        assert "rule" in data, "Rule entries must have a plugin name"
        pname = data.pop("rule")
        p = RulePlugin.get_by_name(pname)(data)
        assert isinstance(p, RulePlugin), "Rule plugins must derive from RulePlugin"
        return p


class RuleIdGenerator:
    """Manage unique rule id generation."""

    __autodoc__ = False

    def __init__(self):
        self._seen = defaultdict(lambda: 0)
        self._rule_seq = 0

    def inject_rule_id(self, ent: dict):
        """
        Modify the supplied dictionary to add a rule_id, but only if a rule_id is not present.

        Keeps track of rule id's and ensures uniqueness, while trying to maintain consistency.
        """

        self._rule_seq += 1
        rule_id = ent.get("rule_id")
        if not rule_id:
            ent_data = json.dumps(ent, sort_keys=True, separators=(",", ":"))
            ent_hash = hashlib.md5(ent_data.encode("utf8")).hexdigest()
            # if the hash is enough, use it, that way it's relocatable and still consistent
            if ent_hash in self._seen:
                # otherwise append a sequence
                ent_hash += "." + str(self._rule_seq)
            rule_id = ent["rule_id"] = ent_hash
        self._seen[rule_id] += 1


class RuleSet(List[RulePlugin]):
    """A list of rules, can reply True, False, or None to an ApprovalRequest

    All rules must pass in a ruleset

    An empty ruleset always returns True
    """

    def approve_request(self, request: ApprovalRequest) -> bool:
        """Return true if all rules return true."""
        for rule in self:  # pylint: disable=not-an-iterable
            try:
                res = rule.approve_request(request)
                if res is None:
                    log.error("unknown request type error in rule %s", rule)
                if not res:
                    return False
            except Exception as ex:
                log.error("error in rule %s: %s", rule, repr(ex))
                return False
        return True

    @classmethod
    def from_list(cls, ruledata: List[dict], rgen: RuleIdGenerator) -> "RuleSet":
        lst = []
        assert isinstance(ruledata, list), "Rulesets must be lists"
        for ent in ruledata:
            rgen.inject_rule_id(ent)
            lst.append(RulePlugin.from_dict(ent))
        return RuleSet(lst)


class RuleTree(List[RuleSet]):
    """A list of RuleSet objects.

    Return True if *any* RuleSet returns True.
    Returns False if all RuleSets return False.
    """

    def approve_request(self, request: ApprovalRequest) -> bool:
        """Return true if any ruleset returns true."""
        for rset in self:  # pylint: disable=not-an-iterable
            res = rset.approve_request(request)
            if res:
                return True
        return False

    @classmethod
    def from_list(cls, ruledefs: List[List[dict]], rgen: RuleIdGenerator) -> "RuleTree":
        ini = []
        for ent in ruledefs:
            rset = RuleSet.from_list(ent, rgen)
            ini.append(rset)
        return RuleTree(ini)


class RuleEngine:
    """A collection of RuleTree objects for each possible request_type.

    Given a request, will dispatch to the correct tree, and return the result.

    If no tree is available, will return None, so the caller can determine the default.
    """

    def __init__(self, rule_map: Dict[RequestType, RuleTree]):
        self.map: Dict[RequestType, RuleTree] = rule_map

    def approve_request(self, request: ApprovalRequest) -> Optional[bool]:
        tree = self.map.get(request.request_type, None)
        if tree is None:
            return None
        return tree.approve_request(request)

    @classmethod
    def from_yml_file(cls, yml: Union["Path", str]):
        """Build a rule engine from a yml file, see `from_dict` for more info."""
        with open(yml, "r", encoding="utf8") as fh:
            info: dict = yaml.safe_load(fh)
            return cls.from_dict(info)

    @classmethod
    def from_dict(
        cls, info: Dict[str, Union[Dict[str, Any], List[List[dict]]]]
    ) -> "RuleEngine":
        """Build a rule engine from a dictionary:

        Example:
        ```
        request_type:
          - - rule: name
              param: val1
            - rule: name2
              param: val2
          - - rule: name
              param: val1
        ```
        """
        rgen = RuleIdGenerator()
        rule_map = {}
        for rtype, treedef in info.items():
            rtype = RequestType(rtype)
            tree = RuleTree.from_list(treedef, rgen)
            rule_map[rtype] = tree
        return cls(rule_map)

    def clear_quota(self, profile: ProfileInfo):
        for rt in self.map.values():
            for rs in rt:
                for rule in rs:
                    rule.clear_quota(profile)
