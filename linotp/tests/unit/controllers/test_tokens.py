from copy import deepcopy

from linotp.controllers.tokens import TokenAdapter

mocked_token = {
    "LinOtp.TokenId": 1,
    "LinOtp.TokenDesc": "123",
    "LinOtp.TokenSerialnumber": "LSQR00011359",
    "LinOtp.TokenType": "qr",
    "LinOtp.TokenInfo": '{\n"partition": 0,\n"state": "pairing_complete",\n"user_token_id": 0,\n"user_public_key": "V8Ulu/s0bnvX3ICR6NMRuqfnBBJbqzclSsGhECa3yVQ=",\n"validity_period_start": "12/12/02 00:01",\n"validity_period_end": "22/11/22 08:28"\n}',
    "LinOtp.IdResolver": "SQLIdResolver.IdResolver.LinOTP_local_admins",
    "LinOtp.IdResClass": "useridresolver.SQLIdResolver.IdResolver.LinOTP_local_admins",
    "LinOtp.Userid": "netgo",
    "LinOtp.OtpLen": 8,
    "LinOtp.MaxFail": 10,
    "LinOtp.Isactive": False,
    "LinOtp.FailCount": 0,
    "LinOtp.Count": 2,
    "LinOtp.CountWindow": 10,
    "LinOtp.SyncWindow": 1000,
    "LinOtp.CreationDate": "Thu, 04 Aug 2022 14:07:35 GMT",
    "LinOtp.LastAuthSuccess": "",
    "LinOtp.LastAuthMatch": "",
    "LinOtp.RealmNames": ["linotp_admins"],
    "User.description": "",
    "User.userid": "netgo",
    "User.username": "netgo",
}

expected_parsed_token = {
    "id": 1,
    "description": "123",
    "serial": "LSQR00011359",
    "type": "qr",
    "creationDate": "2022-08-04T14:07:35+00:00",
    "isActive": False,
    "realms": ["linotp_admins"],
    "tokenConfiguration": {
        "hashLib": None,
        "timeWindow": None,
        "timeShift": None,
        "timeStep": None,
        "countWindow": 10,
        "syncWindow": 1000,
        "otpLength": 8,
        "otpCounter": 2,
    },
    "userInfo": {
        "userId": "netgo",
        "username": "netgo",
        "userDescription": "",
        "idResolverInfo": {
            "resolverName": "LinOTP_local_admins",
            "resolverClass": "SQLIdResolver",
        },
    },
    "usageData": {
        "loginAttempts": None,
        "maxLoginAttempts": None,
        "successfulLoginAttempts": None,
        "maxSuccessfulLoginAttempts": None,
        "lastSuccessfulLoginAttempt": None,
        "failedLoginAttempts": 0,
        "maxFailedLoginAttempts": 10,
        "lastAuthenticationMatch": None,
    },
    "validityPeriod": {
        "validityStart": "2002-12-12T00:01:00+00:00",
        "validityEnd": "2022-11-22T08:28:00+00:00",
    },
}


class TestTokenAdapter:
    def test_to_json_format_full_token(self):
        parsed_token = TokenAdapter(mocked_token).to_JSON_format()
        assert expected_parsed_token == parsed_token

    def test_to_json_format_no_userinfo(self):
        mocked_token_without_userinfo = deepcopy(mocked_token)
        mocked_token_without_userinfo.update(
            {
                "User.userid": "",
                "User.username": "",
            }
        )
        parsed_token = TokenAdapter(mocked_token).to_JSON_format()

        expected_parsed_token_without_userinfo = deepcopy(
            expected_parsed_token
        )
        expected_parsed_token_without_userinfo.update({"userInfo": None})
        assert expected_parsed_token == parsed_token
