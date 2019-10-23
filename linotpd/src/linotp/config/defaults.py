
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
        linotp.model.Config.Key == "linotp." + key).count()

    if count == 0:
        config_entry = linotp.model.Config(key, value,
                                           Type=typ, Description=description)
        Session.add(config_entry)

    elif update:
        config_entry = Session.query(linotp.model.Config).filter(
            linotp.model.Config.Key == "linotp." + key).first()

        if not key.startswith('linotp.'):
            key = 'linotp.' + key

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
        linotp.model.Config.Key == "linotp.Config").count()

    if is_upgrade:
        # if it is an upgrade and no welcome screen was shown before,
        # make sure an upgrade screen is shown
        set_config(key="welcome_screen.version",
                   value="0", typ="text")
        set_config(key="welcome_screen.last_shown",
                   value="0", typ="text")
        set_config(key="welcome_screen.opt_out",
                   value="false", typ="text")

    app.logger.info("Adding config default data...")

    set_config(key="DefaultMaxFailCount",
               value="10", typ="int",
               description=("The default maximum count for"
                            " unsuccessful logins"))

    set_config(key="DefaultCountWindow",
               value="10", typ="int",
               description=("The default lookup window for tokens "
                            "out of sync "))

    set_config(key="DefaultSyncWindow",
               value="1000", typ="int",
               description=("The default lookup window for tokens "
                            "out of sync "))

    set_config(key="DefaultChallengeValidityTime",
               value="120", typ="int",
               description=("The default time, a challenge is regarded"
                            " as valid."))

    set_config(key="DefaultResetFailCount",
               value="True", typ="bool",
               description="The default maximum count for unsucessful logins")

    set_config(key="DefaultOtpLen",
               value="6", typ="int",
               description="The default len of the otp values")

    set_config(key="QRTokenOtpLen",
               value="8", typ="int",
               description="The default len of the otp values")

    set_config(key="QRChallengeValidityTime",
               value="150", typ="int",
               description=("The default qrtoken time, a challenge is regarded"
                            " as valid."))

    set_config(key="QRMaxChallenges",
               value="4", typ="int",
               description="Maximum open QRToken challenges")

    set_config(key="PushChallengeValidityTime",
               value="150", typ="int",
               description=("The pushtoken default time, a challenge is "
                            "regarded as valid."))

    set_config(key="PushMaxChallenges",
               value="4", typ="int",
               description="Maximum open pushtoken challenges")

    set_config(key="PrependPin",
               value="True", typ="bool",
               description="is the pin prepended - most cases")

    set_config(key="FailCounterIncOnFalsePin",
               value="True", typ="bool",
               description="increment the FailCounter, if pin did not match")

    set_config(key="SMSProvider",
               value="smsprovider.HttpSMSProvider.HttpSMSProvider",
               typ="text",
               description="SMS Default Provider via HTTP")

    set_config(key="SMSProviderTimeout",
               value="300", typ="int",
               description="Timeout until registration must be done")

    set_config(key="SMSBlockingTimeout",
               value="30", typ="int",
               description="Delay until next challenge is created")

    set_config(key="DefaultBlockingTimeout",
               value="0", typ="int",
               description="Delay until next challenge is created")

    # setup for totp defaults
    # "linotp.totp.timeStep";"60";"None";"None"
    # "linotp.totp.timeWindow";"600";"None";"None"
    # "linotp.totp.timeShift";"240";"None";"None"

    set_config(key="totp.timeStep",
               value="30", typ="int",
               description="Time stepping of the time based otp token ")

    set_config(key="totp.timeWindow",
               value="300", typ="int",
               description=("Lookahead time window of the time based "
                            "otp token "))

    set_config(key="totp.timeShift",
               value="0", typ="int",
               description="Shift between server and totp token")

    set_config(key="AutoResyncTimeout",
               value="240", typ="int",
               description="Autosync timeout for an totp token")

    # setup for ocra defaults
    # OcraDefaultSuite
    # QrOcraDefaultSuite
    # OcraMaxChallenges
    # OcraChallengeTimeout

    set_config(key="OcraDefaultSuite",
               value="OCRA-1:HOTP-SHA256-8:C-QN08",
               typ="string",
               description="Default OCRA suite for an ocra token ")

    set_config(key="QrOcraDefaultSuite",
               value="OCRA-1:HOTP-SHA256-8:C-QA64",
               typ="string",
               description="Default OCRA suite for an ocra token ")

    set_config(key="OcraMaxChallenges",
               value="4", typ="int",
               description="Maximum open ocra challenges")

    set_config(key="OcraChallengeTimeout",
               value="300", typ="int",
               description="Timeout for an open ocra challenge")

    # emailtoken defaults
    set_config(key="EmailProvider",
               value="linotp.provider.emailprovider.SMTPEmailProvider",
               typ="string",
               description="Default EmailProvider class")

    set_config(key="EmailChallengeValidityTime",
               value="600", typ="int",
               description=("Time that an e-mail token challenge stays valid"
                            " (seconds)"))
    set_config(key="EmailBlockingTimeout",
               value="120", typ="int",
               description="Time during which no new e-mail is sent out")

    set_config(key='OATHTokenSupport',
               value="False", typ="bool",
               description="support for hmac token in oath format")

    # use the system certificate handling, especially for ldaps
    set_config(key="certificates.use_system_certificates",
               value="False", typ="bool",
               description="use system certificate handling")

    set_config(key="user_lookup_cache.enabled",
               value="False", typ="bool",
               description="enable user loookup caching")

    set_config(key="resolver_lookup_cache.enabled",
               value="False", typ="bool",
               description="enable realm resolver caching")

    set_config(key='user_lookup_cache.expiration',
               value="64800", typ="int",
               description="expiration of user caching entries")

    set_config(key='resolver_lookup_cache.expiration',
               value="64800", typ="int",
               description="expiration of resolver caching entries")

    if not is_upgrade:
        set_config(key='NewPolicyEvaluation',
                   value="True", typ="boolean",
                   description="use the new policy engine")

        set_config(key='NewPolicyEvaluation.compare',
                   value="False", typ="boolean",
                   description=("compare the new policy engine with "
                                "the old one"))

    Session.commit()
