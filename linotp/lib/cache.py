import logging

from flask import current_app

from typing import Optional

from linotp.lib.context import request_context as context
from linotp.lib.type_utils import get_duration
from linotp.lib.type_utils import boolean

from beaker.cache import Cache

log = logging.getLogger(__name__)


def get_cache(cache_name: str, scope: str = None) -> Optional[Cache]:
    """
    load the cache with cache_name and scope

    Each cache defines the following configuration parameters:

        linotp.{cache_name}_cache.enabled
            Whether the cache is enabled. Defaults to True
        linotp.{cache_name}_cache.expiration
            How long the entries are cached for in seconds. Defaults to 3 days.

    :remark: This cache is only enabled, if the configuration entry 'enabled'
             evaluates to True and the expiration is of a valid format.
             Expiration format is defined linotp.lib.type_utils

    :param cache_name: the name of the cache
    :param scope: there are related caches, which names are extended by scope
                  used for realm specific caches e.g. for users

    :return: the cache or None if not enabled,

             wrt to typing the cache is not deterministic as the cache type
             is returned by the app.getCacheManager() which could be a beaker
             or something else
    """

    # --------------------------------------------------------------------- --

    # evaluate the config lookup keys

    config = context["Config"]

    config_basename = "linotp." + cache_name + "_cache"
    enabled_entry = config_basename + ".enabled"
    expiration_entry = config_basename + ".expiration"

    # --------------------------------------------------------------------- --

    enabled = boolean(config.get(enabled_entry, True))

    if not enabled:
        return None

    # --------------------------------------------------------------------- --

    # handle expiration format

    expiration_conf = config.get(expiration_entry, 36 * 3600)

    try:
        expiration = get_duration(expiration_conf)

    except ValueError:
        log.info(
            "caching is disabled due to a value error for expiration "
            "definition %r",
            expiration_conf,
        )
        return None

    # --------------------------------------------------------------------- --

    # retrieve the cache from the cache manager

    cache_manager = current_app.getCacheManager()

    if not cache_manager:
        log.info("No Cache Manager found!")
        return None

    cache_fullname = cache_name
    if scope:
        cache_fullname = "%s::%s" % (cache_name, scope)

    resolver_config_cache = cache_manager.get_cache(
        cache_fullname, type="memory", expiretime=expiration
    )

    return resolver_config_cache
