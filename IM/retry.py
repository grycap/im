import time
from functools import wraps


def retry(ExceptionToCheck, ExceptionToAvoid, tries=4, delay=3, backoff=2, logger=None, quiet=True):
    """Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param ExceptionToAvoid: the exception to avoid to check. may be a tuple of
        exceptions to check
    :type ExceptionToAvoid: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
        :param logger: logger to use. If None, print
        :type logger: logging.Logger instance
        :param quiet: flat to specify not to print any message.
        :type quit: bool
    """
    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToAvoid as a:
                    raise (a)
                except ExceptionToCheck as e:
                    if not quiet:
                        msg = "%s, Retrying in %d seconds..." % (
                            str(e), mdelay)
                        if logger:
                            logger.warning(msg)
                        else:
                            print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry
