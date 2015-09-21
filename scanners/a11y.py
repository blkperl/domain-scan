import logging
from scanners import utils
import json
import os
import shlex
from subprocess import Popen, PIPE
import json


command = os.environ.get("PA11Y_PATH", "pa11y")
workers = 1

PA11Y_STANDARD = 'WCAG2AA'

headers = [
    "type",
    "typeCode",
    "code",
    "message",
    "context",
    "selector"
]


def scan(domain, options):
    command = ["pa11y", "--standard", PA11Y_STANDARD, "--reporter", "json", "--level", "none", domain]
    logging.debug("\t %s" % command)
    
    cache = utils.cache_path(domain, "a11y")

    if (options.get("force", False) is False) and (os.path.exists(cache)):
        logging.debug("\tCached.")
        raw = open(cache).read()
        data = json.loads(raw)
        if data.get('invalid'):
            return None

    else:
        raw = utils.scan(command)

        # ?? invalid somehow
        if raw is None:
            utils.write(utils.invalid({}), cache)
            return None

        data = json.loads(raw)
        # Turn it into a dict rather than an array.
        # Using json_for also pretty-prints the JSON to be human-readable.
        data = {'reports': data}
        utils.write(utils.json_for(data), cache)

    for report in data['reports']:
        result = []
        for header in headers:
            result.append(report.get(header))
        yield result
