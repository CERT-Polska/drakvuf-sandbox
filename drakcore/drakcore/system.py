#!/usr/bin/env python

import json
import time

from karton2.base import KartonBase
from karton2.resource import RemoteResource
from karton2.task import Task, TaskState
from karton2 import Config

from drakcore.util import find_config


class SystemServiceConfig(Config):
    def __init__(self, path):
        super(SystemServiceConfig, self).__init__(path)


class SystemService(KartonBase):
    identity = "karton.system"
    GC_INTERVAL = 5

    def __init__(self, config):
        super(SystemService, self).__init__(config=config)
        self.last_gc_trigger = 0

    def gc_list_all_resources(self):
        bucket_name = self.config.minio_config["bucket"]
        return [
            (bucket_name, object.object_name)
            for object in self.minio.list_objects(bucket_name=bucket_name)
        ]

    def gc_list_all_tasks(self):
        return list(filter(None, [
            Task.unserialize(self.rs.get(task_key))
            for task_key in self.rs.keys("karton.task:*")
        ]))

    def gc_collect_resources(self):
        resources = set(self.gc_list_all_resources())
        tasks = self.gc_list_all_tasks()
        for task in tasks:
            for _, resource in task.get_resources():
                # If resource is referenced by task: remove it from set
                if (resource.bucket, resource.uid) in resources:
                    resources.remove((resource.bucket, resource.uid))
        for bucket_name, object_name in list(resources):
            try:
                self.minio.remove_object(bucket_name, object_name)
                self.log.debug("GC: Removed unreferenced resource %s:%s", bucket_name, object_name)
            except Exception:
                self.log.exception("GC: Error during resource removing %s:%s", bucket_name, object_name)

    def gc_collect_finished_tasks(self):
        root_tasks = set()
        running_root_tasks = set()
        tasks = self.gc_list_all_tasks()
        for task in tasks:
            root_tasks.add(task.root_uid)
            if task.status == TaskState.FINISHED:
                self.rs.delete("karton.task:" + task.uid)
                self.log.debug("GC: Finished task %s", task.uid)
            else:
                running_root_tasks.add(task.root_uid)
        for finished_root_task in root_tasks.difference(running_root_tasks):
            # TODO: Notification needed
            self.log.debug("GC: Finished root task %s", finished_root_task)

    def gc_collect(self):
        if time.time() > (self.last_gc_trigger + self.GC_INTERVAL):
            try:
                self.gc_collect_finished_tasks()
                self.gc_collect_resources()
            except Exception:
                self.log.exception("GC: Exception during garbage collection")
            self.last_gc_trigger = time.time()

    def _resource_object(self, bucket, uid):
        return RemoteResource("resource", _uid=uid, bucket=bucket)

    def process_task(self, task):
        bound_identities = set()

        for client in self.rs.client_list():
            bound_identities.add(client["name"])

        self.log.info("[%s] Processing task %s", task.root_uid, task.uid)

        for identity, raw_binds in self.rs.hgetall("karton.binds").items():
            binds = json.loads(raw_binds)
            if identity not in bound_identities:
                self.log.info("Unbound identity detected: %s", identity)

            for bind in binds:
                if task.matches_bind(bind):
                    routed_task = task.fork_task()
                    routed_task.status = TaskState.SPAWNED
                    routed_task_body = routed_task.serialize()
                    self.log.info("[%s] Task %s spawned to %s - %s",
                                  task.root_uid, routed_task.uid, identity, json.dumps(bind))
                    self.rs.set("karton.task:" + routed_task.uid, routed_task_body)
                    self.rs.lpush(identity, routed_task.uid)
                    break

    def process_log(self, body):
        try:
            body = json.loads(body)
            if "task" in body and isinstance(body["task"], str):
                body["task"] = json.loads(body["task"])
            # TODO send to some logz
        except Exception:
            """
            This is log handler exception, so DO NOT USE self.log HERE!
            """
            import traceback
            traceback.print_exc()

    def loop(self):
        self.log.info("Manager {} started".format(self.identity))

        bucket_name = self.config.minio_config["bucket"]
        if not self.minio.bucket_exists(bucket_name):
            self.log.info("Creating bucket {}".format(bucket_name))
            self.minio.make_bucket(bucket_name)

        while True:
            # order does matter! task dispatching must be before karton.operations to avoid races
            data = self.rs.blpop(
                ["karton.logs", "karton.tasks", "karton.operations"],
                timeout=self.GC_INTERVAL,
            )

            if data:
                queue, body = data
                if not isinstance(body, str):
                    body = body.decode("utf-8")
                if queue == "karton.tasks":
                    task = Task.unserialize(self.rs.get("karton.task:" + body))
                    self.process_task(task)
                    task.status = TaskState.FINISHED
                    self.rs.set("karton.task:" + task.uid, task.serialize())
                elif queue == "karton.logs" or queue == "karton.operations":
                    if queue == "karton.operations":
                        # If it is karton.operations queue: update task status
                        operation_body = json.loads(body)
                        task = Task.unserialize(operation_body["task"])
                        task.status = operation_body["status"]
                        self.rs.set("karton.task:" + task.uid, task.serialize())
                    self.process_log(body)

            self.gc_collect()


def main():
    conf = SystemServiceConfig(find_config())
    c = SystemService(conf)
    c.loop()


if __name__ == "__main__":
    main()
