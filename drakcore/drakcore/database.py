import json
from msql import BaseDb
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

AnalysisMetadata = Dict[str, Any]


class Database(BaseDb):
    def select_metadata_by_uid(self, analysis_uid: str) -> Optional[AnalysisMetadata]:
        with self.get_cursor() as cursor:
            cursor.execute("SELECT value FROM metadata WHERE uid = ?", (analysis_uid,))
            result = cursor.fetchone()
            if result:
                return json.loads(result["value"])

    def insert_metadata(self, analysis_uid: str, metadata: AnalysisMetadata):
        with self.get_cursor() as cursor:
            cursor.execute("INSERT INTO metadata (uid, value) VALUES (?, ?)",
                           (analysis_uid, json.dumps(metadata)))

    def get_latest_metadata(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        def into_result(row):
            return dict(id=row["uid"], meta=json.loads(row["value"]))
        with self.get_cursor() as cursor:
            cursor.execute(("SELECT uid, value "
                            "FROM metadata "
                            "ORDER BY json_extract(value, '$.time_finished') DESC "
                            "LIMIT ? "
                            "OFFSET ?"), (limit, offset))
            result = cursor.fetchall()
            return map(into_result, result)
