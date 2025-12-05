import logging
import colorlog
from datetime import datetime
import pytz
import subprocess
import os

logging.getLogger().handlers.clear()

logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_system_timezone():
    try:
        result = subprocess.run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            capture_output=True,
            text=True,
            check=True,
        )
        tz_name = result.stdout.strip()
        return pytz.timezone(tz_name)
    except:
        pass

    try:
        if os.path.exists("/etc/timezone"):
            with open("/etc/timezone", "r") as f:
                tz_name = f.read().strip()
                return pytz.timezone(tz_name)
    except:
        pass

    try:
        if os.path.islink("/etc/localtime"):
            tz_path = os.path.realpath("/etc/localtime")
            tz_name = tz_path.split("/zoneinfo/")[-1]
            return pytz.timezone(tz_name)
    except:
        pass

    try:
        import tzlocal

        return tzlocal.get_localzone()
    except:
        pass

    return pytz.UTC


timezone = get_system_timezone()


class TimezoneFormatter:
    def converter(self, timestamp):
        dt = datetime.fromtimestamp(timestamp, tz=timezone)
        return dt.timetuple()


class ShortNameFormatter(colorlog.ColoredFormatter, TimezoneFormatter):
    def format(self, record):
        parts = record.name.split(".")
        if len(parts) > 1:
            record.shortname = parts[-1]
        else:
            record.shortname = record.name
        return super().format(record)

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone)
        if datefmt:
            return dt.strftime(datefmt)
        else:
            return dt.strftime("%Y-%m-%d %I:%M:%S %p")


colored_handler = colorlog.StreamHandler()
colored_handler.setFormatter(
    ShortNameFormatter(
        "%(asctime)s %(log_color)s%(levelname)-8s%(reset)s [%(shortname)s] %(message_log_color)s%(message)s",
        datefmt="%I:%M:%S %p",
        reset=True,
        log_colors={
            "INFO": "cyan",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
        secondary_log_colors={
            "message": {
                "INFO": "cyan",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red,bg_white",
            }
        },
        style="%",
    )
)
colored_handler.setLevel(logging.INFO)


class ShortNameFilter(logging.Filter):
    def filter(self, record):
        parts = record.name.split(".")
        if len(parts) > 1:
            record.shortname = parts[-1]
        else:
            record.shortname = record.name
        return True


class DebugFormatter(logging.Formatter, TimezoneFormatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone)
        if datefmt:
            return dt.strftime(datefmt)
        else:
            return dt.strftime("%Y-%m-%d %I:%M:%S %p")


debug_handler = logging.StreamHandler()
debug_handler.setFormatter(
    DebugFormatter(
        "%(asctime)s %(levelname)-8s [%(shortname)s] %(message)s", datefmt="%I:%M:%S %p"
    )
)
debug_handler.setLevel(logging.DEBUG)
debug_handler.addFilter(lambda record: record.levelno < logging.INFO)
debug_handler.addFilter(ShortNameFilter())

root_logger = logging.getLogger()
root_logger.addHandler(colored_handler)
root_logger.addHandler(debug_handler)
root_logger.setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)
