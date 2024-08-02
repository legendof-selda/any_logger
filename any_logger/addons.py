from any_logger import logger

global_logger = logger


def use_loguru_logger(log_file: str | None = None, **kwargs):
    """Use loguru for logging. You can access the `loguru.logger` object in `logger.loguru_logger`"""
    from loguru import logger as loguru_logger

    # increasing the depth else it will log within logger scope
    # this will now record the right lines
    _loguru_logger = loguru_logger.opt(depth=1)

    global global_logger
    global_logger.__init__(
        log_function=_loguru_logger.info,
        log_error_function=_loguru_logger.error,
        log_warn_function=_loguru_logger.warning,
        logger_object=_loguru_logger,
    )
    global_logger.loguru_logger = global_logger._logger_object
    if log_file is not None:
        global_logger.loguru_logger.add(log_file, **kwargs)
