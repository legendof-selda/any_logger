"""
This logging module provides a pre-instanced logger to facilitate dealing with logging in Python.
It is simple as:

>>> from any_logger import logger
>>> logger.info("Hello World")

Or create a new Logger which will be used to wrap any logger library of your choice!
Simply initialize your logger library and pass in the `info`, `error` and `warning` log functions
in Loggerinitialization

Example (using loguru):

>>> from loguru import logger as your_logger
>>> from any_logger import Logger
>>> logger = Logger(your_logger.info, your_logger.error, your_logger.warning)
>>>
>>> logger.info("You did it!", "It is super simple!")

You can also use one of the addon functions to set it up quickly!

Example (using loguru):

>>> from any_logger import addons
>>> addons.use_loguru_logger()
>>>
>>> from any_logger import logger
>>> logger.error("oh no")

You can customize the static format template of the messages by changing the `message_format`
attribute. Just make sure you pass in "{message}" inside the format, else the message will not be
printed.

>>> logger.message_format = " | HEADER | " + country + " | {message}"

"""

from any_logger.logger import Logger

__all__ = ["logger"]

logger = Logger()
