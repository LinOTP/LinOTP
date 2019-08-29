
import linotp.model

Session = linotp.model.meta.Session


def set_config(key, value, typ, description=None, update=False):
    '''
    create an intial config entry, if it does not exist

    :param key: the key
    :param value: the value
    :param description: the description of the key

    :return: nothing
    '''

    count = Session.query(linotp.model.Config).filter(
        linotp.model.Config.Key == u"linotp." + key).count()

    if count == 0:
        config_entry = linotp.model.Config(key, value,
                                           Type=typ, Description=description)
        Session.add(config_entry)

    elif update:
        config_entry = Session.query(linotp.model.Config).filter(
            linotp.model.Config.Key == u"linotp." + key).first()

        if not key.startswith('linotp.'):
            key = u'linotp.' + key

        if isinstance(key, str):
            key = key.encode()

        config_entry.Key = key

        if isinstance(value, str):
            value = value.encode()

        config_entry.Value = value

        if isinstance(typ, str):
            typ = typ.encode()

        config_entry.Type = typ

        if isinstance(description, str):
            description = description.encode()

        config_entry.Description = description

        Session.add(config_entry)

    return


def set_defaults(app):
    '''
    add linotp default config settings

    :return: - nothing -
    '''

    is_upgrade = 0 != Session.query(linotp.model.Config).filter(
        linotp.model.Config.Key == u"linotp.Config").count()

    if is_upgrade:
        # if it is an upgrade and no welcome screen was shown before,
        # make sure an upgrade screen is shown
        set_config(key=u"welcome_screen.version",
                   value=u"0", typ=u"text")
        set_config(key=u"welcome_screen.last_shown",
                   value=u"0", typ=u"text")
        set_config(key=u"welcome_screen.opt_out",
                   value=u"false", typ=u"text")

    app.logger.info("Adding config default data...")

    set_config(key=u"DefaultMaxFailCount",
               value=u"10", typ=u"int",
               description=(u"The default maximum count for"
                            u" unsuccessful logins"))

    set_config(key=u"DefaultCountWindow",
               value=u"10", typ=u"int",
               description=(u"The default lookup window for tokens "
                            u"out of sync "))

    set_config(key=u"DefaultSyncWindow",
               value=u"1000", typ=u"int",
               description=(u"The default lookup window for tokens "
                            u"out of sync "))

    set_config(key=u"DefaultChallengeValidityTime",
               value=u"120", typ=u"int",
               description=(u"The default time, a challenge is regarded"
                            u" as valid."))

    set_config(key=u"DefaultResetFailCount",
               value=u"True", typ=u"bool",
               description=u"The default maximum count for unsucessful logins")

    set_config(key=u"DefaultOtpLen",
               value=u"6", typ=u"int",
               description=u"The default len of the otp values")

    set_config(key=u"QRTokenOtpLen",
               value=u"8", typ=u"int",
               description=u"The default len of the otp values")

    set_config(key=u"QRChallengeValidityTime",
               value=u"150", typ=u"int",
               description=(u"The default qrtoken time, a challenge is regarded"
                            u" as valid."))

    set_config(key=u"QRMaxChallenges",
               value=u"4", typ=u"int",
               description=u"Maximum open QRToken challenges")

    set_config(key=u"PushChallengeValidityTime",
               value=u"150", typ=u"int",
               description=(u"The pushtoken default time, a challenge is "
                            u"regarded as valid."))

    set_config(key=u"PushMaxChallenges",
               value=u"4", typ=u"int",
               description=u"Maximum open pushtoken challenges")

    set_config(key=u"PrependPin",
               value=u"True", typ=u"bool",
               description=u"is the pin prepended - most cases")

    set_config(key=u"FailCounterIncOnFalsePin",
               value=u"True", typ=u"bool",
               description=u"increment the FailCounter, if pin did not match")

    set_config(key=u"SMSProvider",
               value=u"smsprovider.HttpSMSProvider.HttpSMSProvider",
               typ=u"text",
               description=u"SMS Default Provider via HTTP")

    set_config(key=u"SMSProviderTimeout",
               value=u"300", typ=u"int",
               description=u"Timeout until registration must be done")

    set_config(key=u"SMSBlockingTimeout",
               value=u"30", typ=u"int",
               description=u"Delay until next challenge is created")

    set_config(key=u"DefaultBlockingTimeout",
               value=u"0", typ=u"int",
               description=u"Delay until next challenge is created")

    # setup for totp defaults
    # "linotp.totp.timeStep";"60";"None";"None"
    # "linotp.totp.timeWindow";"600";"None";"None"
    # "linotp.totp.timeShift";"240";"None";"None"

    set_config(key=u"totp.timeStep",
               value=u"30", typ=u"int",
               description=u"Time stepping of the time based otp token ")

    set_config(key=u"totp.timeWindow",
               value=u"300", typ=u"int",
               description=(u"Lookahead time window of the time based "
                            u"otp token "))

    set_config(key=u"totp.timeShift",
               value=u"0", typ=u"int",
               description=u"Shift between server and totp token")

    set_config(key=u"AutoResyncTimeout",
               value=u"240", typ=u"int",
               description=u"Autosync timeout for an totp token")

    # setup for ocra defaults
    # OcraDefaultSuite
    # QrOcraDefaultSuite
    # OcraMaxChallenges
    # OcraChallengeTimeout

    set_config(key=u"OcraDefaultSuite",
               value=u"OCRA-1:HOTP-SHA256-8:C-QN08",
               typ=u"string",
               description=u"Default OCRA suite for an ocra token ")

    set_config(key=u"QrOcraDefaultSuite",
               value=u"OCRA-1:HOTP-SHA256-8:C-QA64",
               typ=u"string",
               description=u"Default OCRA suite for an ocra token ")

    set_config(key=u"OcraMaxChallenges",
               value=u"4", typ=u"int",
               description=u"Maximum open ocra challenges")

    set_config(key=u"OcraChallengeTimeout",
               value=u"300", typ=u"int",
               description=u"Timeout for an open ocra challenge")

    # emailtoken defaults
    set_config(key=u"EmailProvider",
               value=u"linotp.provider.emailprovider.SMTPEmailProvider",
               typ=u"string",
               description=u"Default EmailProvider class")

    set_config(key=u"EmailChallengeValidityTime",
               value=u"600", typ=u"int",
               description=(u"Time that an e-mail token challenge stays valid"
                            u" (seconds)"))
    set_config(key=u"EmailBlockingTimeout",
               value=u"120", typ=u"int",
               description=u"Time during which no new e-mail is sent out")

    set_config(key=u'OATHTokenSupport',
               value=u"False", typ=u"bool",
               description=u"support for hmac token in oath format")

    # use the system certificate handling, especially for ldaps
    set_config(key=u"certificates.use_system_certificates",
               value=u"False", typ=u"bool",
               description=u"use system certificate handling")

    set_config(key=u"user_lookup_cache.enabled",
               value=u"False", typ=u"bool",
               description=u"enable user loookup caching")

    set_config(key=u"resolver_lookup_cache.enabled",
               value=u"False", typ=u"bool",
               description=u"enable realm resolver caching")

    set_config(key=u'user_lookup_cache.expiration',
               value=u"64800", typ=u"int",
               description=u"expiration of user caching entries")

    set_config(key=u'resolver_lookup_cache.expiration',
               value=u"64800", typ=u"int",
               description=u"expiration of resolver caching entries")

    if not is_upgrade:
        set_config(key=u'NewPolicyEvaluation',
                   value=u"True", typ=u"boolean",
                   description=u"use the new policy engine")

        set_config(key=u'NewPolicyEvaluation.compare',
                   value=u"False", typ=u"boolean",
                   description=(u"compare the new policy engine with "
                                u"the old one"))

    Session.commit()
