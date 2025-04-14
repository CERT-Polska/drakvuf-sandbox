from typing import List

from redis import Redis
from rq.exceptions import NoSuchJobError
from rq.job import Job

ANALYSES_LIST = "drakrun.analyses"
ANALYSES_LIST_LENGTH = 100


def add_analysis_to_recent(
    connection: Redis,
    analysis_id: str,
):
    pipeline = connection.pipeline(transaction=True)
    pipeline.lpush(ANALYSES_LIST, analysis_id)
    pipeline.lrange(ANALYSES_LIST, ANALYSES_LIST_LENGTH, -1)
    dropped_ids = pipeline.execute()[-1]
    if dropped_ids:
        for id in dropped_ids:
            try:
                job = Job.fetch(id, connection=connection)
                if not (job.is_finished or job.is_failed):
                    continue
                job.delete()
            except NoSuchJobError:
                continue
    return True


def get_recent_analysis_list(connection: Redis) -> List[Job]:
    analysis_ids = [
        analysis_id.decode() for analysis_id in connection.lrange(ANALYSES_LIST, 0, -1)
    ]
    jobs = Job.fetch_many(analysis_ids, connection)
    return [job for job in jobs if job is not None]
