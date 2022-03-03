"""Atakama keyserver ruleset library"""
import abc
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Union, TYPE_CHECKING
import logging

import yaml

from atakama import Plugin

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)

class RequestType(Enum):
    DECRYPT = "decrypt"
    SEARCH = "search"
    CREATE_NEW_PROFILE = "create_profile"


@dataclass
class ProfileInfo:
    profile_id: bytes
    """Requesting profile uuid"""
    profile_words: List[str]
    """Requesting profile 'words' mnemonic"""


@dataclass
class ApprovalRequest:
    request_type: RequestType
    """Request type"""
    device_id: bytes
    """Requesting device uuid"""
    profile: ProfileInfo
    """"""
    auth_meta: bytes
    """Authenticated metadata associated with the encrypted data.   Typically a path to a file."""


class RulePlugin(Plugin):
    @abc.abstractmethod
    def approve_request(self, request: ApprovalRequest) -> bool:
        """Return True if the request to decrypt a file will be authorized.
           Return False if the request is to be denied.
           Raise None if the request type is unknown or invalid.
           Exceptions and None are logged, and considered False.

        This is called any time:
            a decryption agent wishes to decrypt a file.
            a decryption agent wishes to search a file.
            a decryption agent wishes to create a new multifactor profile.

        See the RuleRequest class for more information
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
        assert "plugin" in data, "Rule entries must have a plugin name"
        pname = data.pop("plugin")
        p = RulePlugin.get_by_name(pname)(data)
        assert isinstance(p, RulePlugin), "Rule plugins must derive from RulePlugin"
        return p

class RuleSet(List[RulePlugin]):
    """A list of rules, can reply True, False, or None to an ApprovalRequest"""

    def approve_request(self, request: ApprovalRequest) -> bool:
        for rule in self:
            try:
                res = rule.approve_request(request)
                if res is None:
                    log.error("unknown request type error in rule %s", rule)
                return bool(res)
            except Exception as ex:
                log.error("error in rule %s: %s", rule, repr(ex))
                return False

    @classmethod
    def from_list(cls, ruledata: List[dict]) -> "RuleSet":
        lst = []
        assert isinstance(ruledata, list), "Rulesets must be lists"
        for ent in ruledata:
            lst.append(RulePlugin.from_dict(ent))
        return RuleSet(lst)

class RuleTree(List[RuleSet]):
    """A list of RuleSet objects.

    Return True if any RuleSet returns True.
    Returns False if all RuleSets return False.
    """

    def __init__(self, rsets):
        super().__init__(rsets)

    def approve_request(self, request: ApprovalRequest) -> bool:
        for rset in self:
            res = rset.approve_request(request)
            if res:
                return True
        return False

    @classmethod
    def from_list(cls, ruledefs: List[List[dict]]) -> "RuleTree":
        ini = []
        for ent in ruledefs:
            rset = RuleSet.from_list(ent)
            ini.append(rset)
        return cls(ini)

class RuleEngine:
    """A collection of RuleTree objects for each possible request_type.

    Given a request, will dispatch to the correct tree, and return the result.

    If no tree is available, will return None, so the caller can determine the default.
    """

    def __init__(self, rule_map: Dict[RequestType, RuleTree]):
        self.map: Dict[RequestType, RuleTree] = rule_map

    def approve_request(self, request: ApprovalRequest) -> Union[bool, None]:
        tree = self.map.get(request.request_type, None)
        if tree is None:
            return None
        return tree.approve_request(request)

    @classmethod
    def from_yml_file(cls, yml: Union["Path", str]):
        with open(yml, "r", encoding="utf8") as fh:
            info: dict = yaml.safe_load(fh)
            return cls.from_dict(info)

    @classmethod
    def from_dict(cls, info: Dict[str, List[List[dict]]]) -> "RuleEngine":
        map = {}
        for rtype, treedef in info.items():
            rtype = RequestType(rtype)
            tree = RuleTree.from_list(treedef)
            map[rtype] = tree
        return cls(map)

    def clear_quota(self, profile: ProfileInfo):
        for rt in self.map.values():
            for rs in rt:
                for rule in rs:
                    rule.clear_quota(profile)