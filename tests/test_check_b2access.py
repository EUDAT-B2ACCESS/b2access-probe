import json

import pytest
from requests import Response

from check_b2access import getAccessToken, getLdapName, getInfoCert, getTokenInfo, getUserInfo, getInfoUsernamePassword
import requests_mock


class TestProbe:
    def test_get_ldap_name(self):
        name = getLdapName("Apple/Pineapple/Banana  ")
        assert name == "Banana,Pineapple"
        name = getLdapName("Apple/Pineapple/Banana/Oranges  ")
        assert name == "Oranges,Banana,Pineapple"

    def test_get_user_info(self):
        url = "https://some_url"
        token = "token"

        body = json.loads(
            """{
            "sub": "subject",
            "unity:persistent": "PersistentID"
            }
            """
        )

        with requests_mock.Mocker() as m:
            m.get(url, json=body, status_code=200)
            getUserInfo(url, token, True)

    @pytest.mark.parametrize("status_code, body", [
        [200, '{"sub": "subject"}'],  # missing persistent ID
        [200, '{"unity:persistent": "PersistentID"}'],  # missing subject
        [500, '{"sub": "subject", "unity:persistent": "PersistentID"}']  # Server Error
    ])
    def test_get_user_info_exception(self, status_code, body):
        body = json.loads(body)
        url = "https://some_url"
        token = "token"

        with pytest.raises(SystemExit) as e:
            with requests_mock.Mocker() as m:
                m.get(url, json=body, status_code=status_code)
                getUserInfo(url, token, True)
