import json
import logging
from pathlib import PurePosixPath
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader

log = logging.getLogger(__name__)


def make_pdb_profile(file_path, pdbname):
    ctx = Context()
    uripath = PurePosixPath(file_path).as_uri()
    return json.dumps(
        PdbReader(ctx, uripath, database_name=pdbname).get_json(),
        indent=4
    )
