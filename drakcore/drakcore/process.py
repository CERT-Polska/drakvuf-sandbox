from karton.core import Karton

from drakcore.app import get_analysis_metadata
from drakcore.version import __version__ as DRAKCORE_VERSION

# TODO: Why is this even needed?
#       Right now there's no easy way to get a list of analyses,
#       so we need to keep an eye on drakrun to catch metadata
#       from finished analysis and place them in the internal
#       database.


class AnalysisProcessor(Karton):
    version = DRAKCORE_VERSION
    identity = "karton.drakrun.processor"
    filters = [{"type": "analysis", "kind": "drakrun"}]

    def process(self, task):
        analysis_uid = task.payload["analysis_uid"]
        # Trigger metadata request, thus pulling it into cache
        get_analysis_metadata(analysis_uid)


def main():
    AnalysisProcessor().loop()


if __name__ == "__main__":
    main()
