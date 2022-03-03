import json

import yaml

from atakama import (
    RulePlugin, RuleSet, ApprovalRequest, RequestType, ProfileInfo, RuleEngine, RuleTree, MetaInfo
)


class TestMetaInfo(MetaInfo):
    def __init__(self, meta="/meta", complete=True):
        super().__init__(meta=meta, complete=complete)

class TestProfileInfo(ProfileInfo):
    def __init__(self, profile_id=b'pid', profile_words=None):
        profile_words = profile_words or ["w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"]
        super().__init__(profile_id=profile_id, profile_words=profile_words)


class TestApprovalRequest(ApprovalRequest):
    def __init__(self, request_type=RequestType.DECRYPT, device_id=b'did', profile=TestProfileInfo(),
                 auth_meta=None):
        auth_meta = auth_meta or [TestMetaInfo()]
        super().__init__(request_type=request_type, device_id=device_id, profile=profile, auth_meta=auth_meta)

def test_simple_rule():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example"

        def approve_request(self, request):
            if request.device_id == b'3':
                return True
            return False

    rs = RuleSet([ExampleRule({})])

    assert rs.approve_request(TestApprovalRequest(device_id=b'3'))
    assert not rs.approve_request(TestApprovalRequest(device_id=b'4'))

def test_errs():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example"

        def approve_request(self, request):
            if request.device_id == b'3':
                return True
            if request.device_id == b'b':
                raise ValueError
            return None

    rs = RuleSet([ExampleRule({})])

    assert rs.approve_request(TestApprovalRequest(device_id=b'3'))
    assert rs.approve_request(TestApprovalRequest(device_id=b'4')) is False
    assert rs.approve_request(TestApprovalRequest(device_id=b'b')) is False


def test_simple_loader(tmp_path):
    # noinspection PyUnusedLocal
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example_loader"

        def __init__(self, args):
            self.okid = bytes.fromhex(args["device_id"])
            super().__init__(args)

        def approve_request(self, request):
            if request.device_id == self.okid:
                return True
            return False

    rule_yml = tmp_path / "rules.yml"
    info = {RequestType.DECRYPT.value: [[{"plugin": "example_loader", "device_id": b'okdid'.hex()}]]}
    with rule_yml.open("w") as f:
        yaml.safe_dump(info, f)

    rs = RuleEngine.from_yml_file(rule_yml)

    assert rs.approve_request(TestApprovalRequest(device_id=b'okdid'))
    assert not rs.approve_request(TestApprovalRequest(device_id=b'whatever'))

def test_more_complex(tmp_path):
    # noinspection PyUnusedLocal
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "complex"

        def approve_request(self, request):
            did = bytes.fromhex(self.args.get("device_id", ""))
            meta = self.args.get("path", "")
            return request.device_id == did and (not meta or request.auth_meta[0].meta == meta)

    rule_yml = tmp_path / "rules.yml"
    info = {
        RequestType.DECRYPT.value: [
            [{"plugin": "complex", "device_id": b'okwmeta'.hex()}, {"plugin": "complex", "path": "/meta"}],
            [{"plugin": "complex", "device_id": b'okany'.hex()}]
        ],
        RequestType.SEARCH.value: [
            [{"plugin": "complex", "device_id": b'okwmeta'.hex()}, {"plugin": "complex", "path": "/search"}],
            [{"plugin": "complex", "device_id": b'okany'.hex()}]
        ]
    }

    with rule_yml.open("w") as f:
        json.dump(info, f)

    rs = RuleEngine.from_yml_file(rule_yml)

    assert rs.approve_request(TestApprovalRequest(device_id=b'okany'))
    assert rs.approve_request(TestApprovalRequest(device_id=b'okwmeta', auth_meta=[TestMetaInfo("/meta")]))
    assert rs.approve_request(TestApprovalRequest(device_id=b'okwmeta', auth_meta=[TestMetaInfo("/search")]))
    assert not rs.approve_request(TestApprovalRequest(device_id=b'notok', auth_meta=[TestMetaInfo("/search")]))
    assert not rs.approve_request(TestApprovalRequest(device_id=b'notok', auth_meta=[TestMetaInfo("/meta")]))


def test_clear_quota():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        quota = {}

        @staticmethod
        def name():
            return "quota"

        def approve_request(self, request):
            self.quota[request.profile.profile_id] = self.quota.get(request.profile.profile_id, 0) + 1
            return self.quota[request.profile.profile_id] <= self.args["limit"]

        def clear_quota(self, profile: ProfileInfo) -> None:
            self.quota.pop(profile.profile_id, None)

    rs = RuleSet([ExampleRule({"limit": 2})])
    re = RuleEngine({RequestType.DECRYPT: RuleTree([rs])})

    assert re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid1')))
    assert re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid1')))
    assert not re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid1')))
    assert re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid2')))
    assert re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid2')))
    assert not re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid2')))

    re.clear_quota(TestProfileInfo(profile_id=b'pid1'))

    # other request types are ignored, and don't impact quota
    assert re.approve_request(TestApprovalRequest(request_type=RequestType.SEARCH, profile=TestProfileInfo(profile_id=b'pid1'))) is None
    assert re.approve_request(TestApprovalRequest(request_type=RequestType.SEARCH, profile=TestProfileInfo(profile_id=b'pid1'))) is None
    assert re.approve_request(TestApprovalRequest(request_type=RequestType.SEARCH, profile=TestProfileInfo(profile_id=b'pid1'))) is None

    # pid 1 is still clear
    assert re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid1')))

    # pid 2 is not
    assert not re.approve_request(TestApprovalRequest(profile=TestProfileInfo(profile_id=b'pid2')))
