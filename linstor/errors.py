class LinstorError(Exception):
    """
    Linstor basic error class with a message
    """
    def __init__(self, msg, all_errors=None):
        self._msg = msg
        if all_errors is None:
            all_errors = []
        self._errors = all_errors

    def all_errors(self):
        return self._errors

    @property
    def message(self):
        return self._msg

    def __str__(self):
        return "Error: {msg}".format(msg=self._msg)

    def __repr__(self):
        return "LinstorError('{msg}')".format(msg=self._msg)


class LinstorNetworkError(LinstorError):
    """
    Linstor Error indicating an network/connection error.
    """
    def __init__(self, msg, more_errors=None):
        super(LinstorNetworkError, self).__init__(msg, more_errors)


class LinstorTimeoutError(LinstorError):
    """
    Linstor network timeout error
    """
    def __init__(self, msg, more_errors=None):
        super(LinstorTimeoutError, self).__init__(msg, more_errors)


class LinstorApiCallError(LinstorError):
    """
    Linstor error from an apicall response.
    """
    def __init__(self, apicallresponse, all_errors=None):
        """

        :param ApiCallResponse apicallresponse:
        :param list[ApiCallResponse] all_errors:
        """
        super(LinstorApiCallError, self).__init__(str(apicallresponse), all_errors if all_errors else [apicallresponse])

        self._main_error = apicallresponse

    @property
    def main_error(self):
        return self._main_error


class LinstorArgumentError(LinstorError):
    """
    Linstor error if an argument for a function call is invalid.
    """
    def __init__(self, msg, more_errors=None):
        super(LinstorArgumentError, self).__init__(msg, more_errors)


class LinstorReadOnlyAfterSetError(LinstorError):
    """
    Linstor error raised if a property that is only allowed to be set once, is re-set.
    """
    def __init__(self, msg=None, more_errors=None):
        if msg is None:
            msg = 'After this property got set it is read-only'
        super(LinstorReadOnlyAfterSetError, self).__init__(msg, more_errors)
