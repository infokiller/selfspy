import logging
import logging.handlers
import time

_LOG_FMT = '%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] %(message)s'
_LOG_FORMATTER = logging.Formatter(_LOG_FMT)

logger = logging.getLogger()


def init_logger(name: str) -> None:
    stdout_handler = logging.StreamHandler()
    stdout_formatter = logging.Formatter(_LOG_FMT)
    stdout_handler.setFormatter(stdout_formatter)
    logger.addHandler(stdout_handler)
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    syslog_formatter = logging.Formatter('{}: {}'.format(name, _LOG_FMT))
    syslog_formatter.ident = name
    syslog_handler.setFormatter(syslog_formatter)
    logger.addHandler(syslog_handler)


# pylint: disable=invalid-name
_indent = 0


def _increment_indent():
    # pylint: disable=global-statement,invalid-name
    global _indent
    _indent += 1


def _decrement_indent():
    # pylint: disable=global-statement,invalid-name
    global _indent
    _indent -= 1


# pylint: disable=too-many-instance-attributes
class DurationLogger:

    # pylint: disable=too-many-arguments
    def __init__(self,
                 prefix,
                 log_level=logging.INFO,
                 increment_indent=True,
                 precision=3):
        self.prefix = prefix
        self.log_level = log_level
        self.increment_indent = increment_indent
        self.precision = precision
        self.before = None
        self.before_perf = None
        self.indent_str = None

    def start(self):
        self.indent_str = _indent * '  '
        if self.increment_indent:
            _increment_indent()
        self.before = time.process_time()
        self.before_perf = time.perf_counter()
        return self

    def finish(self):
        if self.increment_indent:
            _decrement_indent()
        duration = time.perf_counter() - self.before_perf
        msg = (f'{self.indent_str}{self.prefix} took '
               f'{duration:.{self.precision}f} sec')
        cpu_duration = time.process_time() - self.before
        if cpu_duration > 1.1 * duration or cpu_duration < 0.9 * duration:
            msg += f', {cpu_duration:.{self.precision}f} CPU sec'
        # TODO: log the calling function name by overriding logger.findCaller in
        # a custom logger class.
        logger.log(self.log_level, msg)
