# [atakama](atakama.md).rule_engine
Atakama keyserver ruleset library


[(view source)](https://github.com/AtakamaLLC/atakama_sdk/blob/master/atakama/rule_engine.py)
## ApprovalRequest(object)
ApprovalRequest(request_type: atakama.rule_engine.RequestType, device_id: bytes, profile: atakama.rule_engine.ProfileInfo, auth_meta: List[atakama.rule_engine.MetaInfo], cryptographic_id: bytes)



## MetaInfo(object)
MetaInfo(meta: str, complete: bool)



## ProfileInfo(object)
ProfileInfo(profile_id: bytes, profile_words: List[str])



## RequestType(Enum)
An enumeration.



## RuleEngine(object)
A collection of RuleTree objects for each possible request_type.

Given a request, will dispatch to the correct tree, and return the result.

If no tree is available, will return None, so the caller can determine the default.




## RulePlugin(Plugin)

Base class for key server approval rule handlers.

When a key server receives a request, rules are consulted for approval.

Each rule receives its configuration from the policy file,
not the atakama config, like other plugins.

In addition to standard arguments from the policy, file a unique
`rule_id` is injected, if not present.



#### .approve_request(self, request: atakama.rule_engine.ApprovalRequest) -> Optional[bool]

Return True if the request to decrypt a file will be authorized.

Return False if the request is to be denied.
Raise None if the request type is unknown or invalid.
Exceptions and None are logged, and considered False.

This is called any time:
    a decryption agent wishes to decrypt a file.
    a decryption agent wishes to search a file.
    a decryption agent wishes to perform other multifactor request types.

See the RequestType class for more information.


#### .check_quota(self, profile: atakama.rule_engine.ProfileInfo) -> bool

Returns False if the profile will not be approved in the next request.
Returns True if the profile *may* be approved for access, and is not past a limit.

This is not a guarantee of future approval, it's a way of checking to see if any users have
reached any limits, quotas or other stateful things for reporting purposed.


#### .clear_quota(self, profile: atakama.rule_engine.ProfileInfo) -> None

Reset or clear any limits, quotas, access counts, bytes-transferred for a given profile.

Used by an administrator to "clear" or "reset" a user that has hit limits.



## RuleSet(list)
A list of rules, can reply True, False, or None to an ApprovalRequest

All rules must pass in a ruleset

An empty ruleset always returns True



#### .approve_request(self, request: atakama.rule_engine.ApprovalRequest) -> bool
Return true if all rules return true.


## RuleTree(list)
A list of RuleSet objects.

Return True if *any* RuleSet returns True.
Returns False if all RuleSets return False.



#### .approve_request(self, request: atakama.rule_engine.ApprovalRequest) -> bool
Return true if any ruleset returns true.


