import requests
from typing import Tuple


class Client(object):
    """
    Simple API client for DRAKVUF Sandbox

    Modeled after:
    - https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/examples/push_sample.py
    - https://stackoverflow.com/questions/16694907/download-large-file-in-python-with-requests
    """

    def __init__(self, url: str):
        """
        Constructor

        Args:
            url (str): the URL of the server e.g. http://localhost:6300
        """
        # create URLs
        self.base_url = url
        self.upload_url = f"{self.base_url}/upload"
        self.status_url = f"{self.base_url}/status"
        self.dump_url = f"{self.base_url}/dumps"
        self.log_url = f"{self.base_url}/logs"

    def post_file(self, path: str) -> str:
        """
        Submits a file

        Args:
            path (str):

        Returns:
            str: the task UUID
        """
        with open(path, 'rb') as sample:
            response = requests.post(self.upload_url, files={'file': sample})
            response.raise_for_status()
        json = response.json()
        try:
            return json['task_uid']
        except KeyError:
            raise KeyError("'task_uid' not in the JSON response")

    def get_status(self, uuid: str) -> str:
        """
        Retrieve status of analysis job

        Args:
            uuid (str): the UUID to retrieve a status for

        Returns:
            str: the status (e.g. 'pending')
        """
        url = f"{self.status_url}/{uuid}"
        response = requests.get(url)
        response.raise_for_status()
        json = response.json()
        try:
            return json['status']
        except KeyError:
            raise KeyError("'status' not in the JSON response")

    def get_dump(self, uuid: str) -> Tuple[int, str]:
        """
        Download the mem dump for the given analysis

        Args:
            uuid (str): the UUID of the analysis

        Returns:
            tuple: an int (status code) and a str (filename written to)

        """
        url = f"{self.dump_url}/{uuid}"
        outfilepath = f"{uuid}.dump"
        return Client.download_file(url, outfilepath)

    def get_log(self, uuid: str, logname: str) -> Tuple[int, str]:
        """
        Download a log file for a given analysis

        Args:
            uuid (str): the UUID of the analysis
            logname (str): the name of the log (e.g. apimon)

        Returns:
            tuple: an int (status code) and a str (filename written to)

        """
        url = f"{self.log_url}/{uuid}/{logname}"
        outfilepath = f"{uuid}-{logname}.json"
        return Client.download_file(url, outfilepath)

    @staticmethod
    def download_file(url: str, filepath: str) -> Tuple[int, str]:
        """
        Downloads a file from a URL in chunks and writes it to disk

        Args:
            url (str): the URL
            filepath (str): the file to write to

        Returns:
            tuple: an int (status code) and a str (filename written to)

        """
        with requests.get(url, stream=True) as response:
            response.raise_for_status()
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        return response.status_code, filepath
