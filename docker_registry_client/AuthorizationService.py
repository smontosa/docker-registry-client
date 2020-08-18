try:
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit

try:
    # python_version >= 3.2
    from functools import lru_cache
except ImportError:
    # python_version <= 3.2
    # this dummy decorator does no cache at all, only imitates api.
    def lru_cache(maxsize=128, typed=False):
        def decorating_function(user_function):
            return user_function

        def cache_clear():
            pass

        decorating_function.cache_clear = cache_clear
        return decorating_function

# import urlparse
import requests
import logging

logger = logging.getLogger(__name__)

@lru_cache(maxsize=256, typed=False)
def _request_token(auth, registry, url, scope, verify, timeout):
    """
    Cached function that separates token call from AuthorizationService instance.
    :param auth:     ``(username, password)`` tuple,
    :param registry: ``string``, registry name
    :param url: ``string``, url for the authentication service
    :param scope: ``None`` or ``string``, requesting scope
    :param verify: ``boolean``, ssl verifivation
    :param timeout: number of seconds to wait until timeout

    :return: ``string``, token, or empty if failed
    """
    rsp = requests.get(
        (
            "%s?service=%s&scope=%s" % (url, registry, scope)
            if scope is not None else
            "%s?service=%s" % (url, registry)
        ),
        auth=auth,
        verify=verify,
        timeout=timeout
    )

    if not rsp.ok:
        logger.error("Can't get token for authentication")
        return ""

    return rsp.json()['token']


class AuthorizationService(object):
    """This class implements a Authorization Service for Docker registry v2.

    Specification can be found here :
    https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md

    The idea is to delegate authentication to a third party and use a token to
    authenticate to the registry. Token has to be renew each time we change
    "scope".
    """
    def __init__(self, registry="", url="", auth=None, verify=False,
                 api_timeout=None):
        # Leaving registry name passing due to backward compatibility.
        # In fact this should not be specified by a client.
        # Registry ip:port
        self._registry = urlsplit(registry).netloc
        # Leaving url passing due to backward compatibility. In fact this should not be specified by a client.
        # Service url, ip:port
        self._url = url
        # Authentication (user, password) or None. Used by request to do
        # basicauth
        self.auth = auth
        # Timeout for HTTP request
        self.api_timeout = api_timeout

        # Usage of self.desired_scope attribute is now deprecated. It stays equal to the scope for the
        # latest token used, and equal to the empty string just after init
        self.desired_scope = ""

        # Usage of self.scope is now deprecated. It stays equal to the last desired scope.
        self.scope = ""

        # Usage of self.token is now deprecated. It is equal to the latest token used.
        self.token = ""

        # Boolean to enfore https checks. Used by request
        self.verify = verify

        # # If we have no url then token are not required. get_new_token will not
        # # be called
        if url:
            split = urlsplit(url)
            # user in url will take precedence over giver username
            # will be performed here only once. url setter will not trigger this
            if split.username and split.password:
                self.auth = (split.username, split.password)
        #
        #     self.token_required = True
        # else:
        #     self.token_required = False

    @property
    def registry(self):
        return self._registry

    @registry.setter
    def registry(self, registry_name):
        self._registry = registry_name

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, url_string):
        self._url = url_string

    def get_token(self, scope, force_new_token=False):
        """
        Will return token that authorizes logged user. Uses ``self.registry`` and ``self.url`` to determine
        target URI.

        :param scope: ``None`` or ``string`` that represents desired scope.
        :param force_new_token: ``boolean``, indicates usage of cache.

        :returns: ``string``, requested token or empty if failed.
        """
        # usage of this `desired_scope` and `scope` attr is now deprecated. Its behaviour should be still the
        # same by use of following two lines:
        self.scope = self.desired_scope
        self.desired_scope = scope

        if force_new_token:
            # this is very naive implementation, needs upgrades to clear only user specific cache
            _request_token.clear_cache()

        try:
            auth_view = (self.auth[0], "****")
        except TypeError:
            auth_view = None

        logger.debug(
            "Requesting token (force: %s): auth=%s, registry=%s, url=%s, scope=%s, verify=%s, timeout=%s" %
            (force_new_token, auth_view, self.registry, self.url, scope, self.verify, self.api_timeout)
        )

        token = _request_token(
            auth=self.auth,
            registry=self.registry,
            url=self.url,
            scope=scope,
            verify=self.verify,
            timeout=self.api_timeout
        )
        logger.debug(
            "Got token: %s" % (token,)
        )

        # Usage of self.token is now deprecated. This line is used for backward compatibility.
        self.token = token

        return token

    def get_new_token(self):
        """
        This method is now deprecated. Use :py:func:`.get_token` in new integrations.
        """
        rsp = requests.get("%s/v2/token?service=%s&scope=%s" %
                           (self.url, self.registry, self.desired_scope),
                           auth=self.auth, verify=self.verify,
                           timeout=self.api_timeout)
        if not rsp.ok:
            logger.error("Can't get token for authentication")
            self.token = ""

        # Usage of self.token is now deprecated. It is equal to the latest token used.
        self.token = rsp.json()['token']
        # We managed to get a new token, update the current scope to the one we
        # wanted
        # Usage of self.desired_scope attribute is now deprecated. It stays equal to the scope for the
        # latest token used, and equal to the empty string just after init
        self.scope = self.desired_scope
