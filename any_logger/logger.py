import functools
import logging
import traceback
from inspect import isclass, iscoroutinefunction, isgeneratorfunction
from sys import stderr, stdout
from typing import Callable, Optional

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# The background is set with 40 plus the number of the color, and the foreground with 30

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"
COLORS = {"WARNING": YELLOW, "INFO": WHITE, "DEBUG": BLUE, "CRITICAL": RED, "ERROR": RED}
MSG = f"%(asctime)s [{BOLD_SEQ}%(levelname)-18s{RESET_SEQ}] ({BOLD_SEQ}%(filename)s{RESET_SEQ}:%(lineno)d) %(message)s"


class LevelFilter(logging.Filter):
    def __init__(self, low, high):
        self._low = low
        self._high = high
        logging.Filter.__init__(self)

    def filter(self, record):  # noqa: A003
        if self._low <= record.levelno <= self._high:
            return True
        return False


class ColorFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(MSG)

    def format(self, record):  # noqa: A003
        levelname = record.levelname
        if levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return super().format(record)


def wrap_log_function(log_fn):
    @functools.wraps(log_fn)
    def wrapped(msg: str, **kwargs):
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 2
        return log_fn(msg, **kwargs)

    return wrapped


class Logger:
    """This class acts like a wrapper to your logger library of your choice!
    Using this we can switch to any logging library easily and by default, all logs goes to
    standard library loggers
    """

    def __init__(
        self,
        log_function: Callable | None = None,
        log_error_function: Callable | None = None,
        log_warn_function: Callable | None = None,
        logger_object: logging.Logger | None = None,
        message_format: str | None = None,
        log_debug_function: Callable | None = None,
    ):
        """Initialize the Logging Wrapper class by passing the functions of the logging object directly!
        NOTE: For message_format, the format must contain "{message}" in it else the message which
        needs to logged will be missing.

        Args:
            log_function (Callable, optional): The function that is called for logging information.
                    Defaults to `logger_object.info`.
            log_error_function (Callable, optional): The function that is called for logging
                    errors. Defaults to `logger_object.error`.
            log_warn_function (Callable, optional): The function that is called for logging
                    warnings. Defaults to `logger_object.warning`.
            logger_object (object, optional): Holds the actual logging object. Defaults to a newly
                    created one with a few custom settings, like separate stdout and stderr streams
                    and colorized output.
            message_format (str, optional): The format template used for logging messages. Defaults
                    to "{message}".
        """
        self._log_function = log_function
        self._log_error_function = log_error_function
        self._log_warn_function = log_warn_function
        self._log_debug_function = log_debug_function
        if log_function is None and log_error_function is None and log_warn_function is None:
            if logger_object is None:
                logger_object = logging.getLogger(__name__)
                logger_object.propagate = False
                logger_object.setLevel(logging.DEBUG)
                logger_object.handlers.clear()
                stdout_handler = logging.StreamHandler(stdout)
                stdout_handler.addFilter(LevelFilter(logging.NOTSET, logging.INFO))
                stdout_handler.setLevel(logging.NOTSET)
                stdout_handler.setFormatter(ColorFormatter())
                logger_object.addHandler(stdout_handler)
                stderr_handler = logging.StreamHandler(stderr)
                stderr_handler.addFilter(LevelFilter(logging.WARNING, logging.CRITICAL))
                stderr_handler.setLevel(logging.WARNING)
                stderr_handler.setFormatter(ColorFormatter())
                logger_object.addHandler(stderr_handler)
            self._log_function = wrap_log_function(logger_object.info)
            self._log_error_function = wrap_log_function(logger_object.error)
            self._log_warn_function = wrap_log_function(logger_object.warning)
            self._log_debug_function = wrap_log_function(logger_object.debug)
        self._logger_object = logger_object
        self.message_format = message_format

    def _message(self, *values: object, sep: str, end: str) -> str:
        """
        Combines all messages for printing into a single string. This is useful for most loggers
        since they accept single values.

        Convert each object into its str equivalent and concat them together into a single object.

        Args:
            sep (str): string inserted between values, defaults to a space.
            end (str): string appended after the last value, defaults to an empty string.

        Returns:
            str: returns the jonined single variable message.
        """
        message = ""
        for i in range(len(values)):
            message += str(values[i])
            if (i + 1) != len(values):
                message += sep
        message += end
        return message if self.message_format is None else self.message_format.format(message=message)

    def debug(self, *values: object, sep: Optional[str] = " ", end: Optional[str] = None, **kwargs):
        """Logs the values to a logger object, or to sys.stdout by default.

        Args:
            *values: objects to log.
            sep (str, optional): string inserted between values, defaults to a space.
            end (str, optional): string appended after the last value, defaults to an empty string
            **kwargs: Arbitrary keyword arguments useful for logger library.
        """
        sep = "" if sep is None else sep
        end = "" if end is None else end
        if self._log_function is None:
            print(*values, sep=sep, end=end)
        else:
            self._log_debug_function.__call__(self._message(*values, sep=sep, end=end), **kwargs)

    def info(self, *values: object, sep: Optional[str] = " ", end: Optional[str] = None, **kwargs):
        """Logs the values to a logger object, or to sys.stdout by default.

        Args:
            *values: objects to log.
            sep (str, optional): string inserted between values, defaults to a space.
            end (str, optional): string appended after the last value, defaults to an empty string
            **kwargs: Arbitrary keyword arguments useful for logger library.
        """
        sep = "" if sep is None else sep
        end = "" if end is None else end
        if self._log_function is None:
            print(*values, sep=sep, end=end)
        else:
            self._log_function.__call__(self._message(*values, sep=sep, end=end), **kwargs)

    def error(self, *values: object, sep: Optional[str] = " ", end: Optional[str] = None, **kwargs):
        """Logs the values as error to a logger object, or to sys.stdout by default.

        Args:
            *values: objects to log as error.
            sep (str, optional): string inserted between values, defaults to a space.
            end (str, optional): string appended after the last value, defaults to an empty string
            **kwargs: Arbitrary keyword arguments useful for logger library.
        """
        sep = "" if sep is None else sep
        end = "" if end is None else end
        if self._log_error_function is None:
            print(*values, sep=sep, end=end, file=stderr)
        else:
            self._log_error_function.__call__(self._message(*values, sep=sep, end=end), **kwargs)

    def warning(self, *values: object, sep: Optional[str] = " ", end: Optional[str] = None, **kwargs):
        """Logs the values as warning to a logger object, or to sys.stdout by default.

        Args:
            *values: objects to log as warning.
            sep (str, optional): string inserted between values, defaults to a space.
            end (str, optional): string appended after the last value, defaults to an empty string
            **kwargs: Arbitrary keyword arguments useful for logger library.
        """
        sep = "" if sep is None else sep
        end = "" if end is None else end
        if self._log_warn_function is None:
            print(*values, sep=sep, end=end)
        else:
            self._log_warn_function.__call__(self._message(*values, sep=sep, end=end), **kwargs)

    def exception(self, exc: Exception, message: str = "An error has been caught", **kwargs):
        """Logs the Exception exc object with proper traceback stack formatting as and error.
        ```
        try:
            raise ValueError()
        except ValueError as e:
            logger.exception(e, 'A value error occured!')
        ```

        Args:
            exc (Exception): The exception caught in a try except block
            message (str, optional): A message to be printed along with the traceback
        """
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
        self.error("Error occured!", message, type(exc), exc, sep="\n", **kwargs)
        self.error(*traceback.format_exception(exc), sep="\n", **kwargs)

    def catch(
        self,
        exceptions: tuple[type[Exception], ...] = (Exception,),
        reraise: bool = True,
        on_error: Callable | None = None,
        exclude: tuple[type[Exception], ...] | None = None,
        message: str = "An error has been caught",
        default=None,
    ):
        """Returns a decorator which logs exceptions automatically. Useful to ensure runtime exceptions are logged.
        The entire program can be decorated to log all issues.

        Args:
            exceptions (Tuple[Exception], optional): A tuple of exceptions which must be handled.
                    If the exceptions occured is not of this type, it will reraise. Defaults to
                    Exception.
            reraise (bool, optional): When an error occurs and logged, should it be raised again to
                    halt runtime? Defaults to True.
            on_error (Callable, optional): On error, this function will be called after its logged.
                    It can only have a single argument which is the exceptions object. Defaults to
                    None.
            exclude (Tuple[Exception], optional): The exceptions that are explicitly ignored.
                    Defaults to None.
            message (str, optional): A message to be logged when an error occurs.
            default ([type], optional): The default value returned if an error occurred without
                    being re-raised. Defaults to None.
        """

        # method overloading
        if callable(exceptions) and not (isclass(exceptions) and issubclass(exceptions, BaseException)):
            return self.catch()(exceptions)

        def decorator(function):
            def handleit(e):
                if not issubclass(type(e), exceptions):
                    raise e
                if exclude is not None and issubclass(type(e), exclude):
                    raise e
                self.exception(e, message)
                if on_error is not None:
                    on_error(e)
                if reraise:
                    raise e
                return default

            if iscoroutinefunction(function):

                @functools.wraps(function)
                async def wrapper(*args, **kwargs):
                    try:
                        return await function(*args, **kwargs)
                    except Exception as e:
                        return handleit(e)

            elif isgeneratorfunction(function):

                @functools.wraps(function)
                def wrapper(*args, **kwargs):
                    try:
                        return (yield from function(*args, **kwargs))
                    except Exception as e:
                        return handleit(e)

            else:

                @functools.wraps(function)
                def wrapper(*args, **kwargs):
                    try:
                        return function(*args, **kwargs)
                    except Exception as e:
                        return handleit(e)

            return wrapper

        return decorator

    def __repr__(self):
        repr_self = super().__repr__()
        if self._logger_object is not None:
            repr_self += "\n" + repr(self._logger_object)
        return repr_self
