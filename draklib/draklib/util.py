import logging
import subprocess
import traceback

log = logging.getLogger("drakrun")


def try_run(
    list_args: list, msg: str, reraise=True, **kwargs
) -> subprocess.CompletedProcess:
    """
    Runs subprocess.run in a try except with some default arguments ( which can be overriden by supplying kwargs )

            Parameters:
                    list_args (list): Subprocess list which will be passed to subprocess.run
                    msg (str): A meaningful error message to be raised during non-zero exit code
                    reraise (bool):
                        True: will raise an Exception with traceback on error
                        False: will log a warning on error
                    **kwargs: additional parameters to be passed to subprocess.run

            Defaults:
                    subprocess.run is called with the following arguments by default
                    stderr = subprocess.PIPE
                    stdout = subprocess.PIPE # to print to console, pass kwargs ( stdout = None )
                    check = True

            Returns:
                    sub (subprocess.CompletedProcess): Object with the completed process
                        or
                    None: if the subprocess failed and reraise=False
    """

    try:
        kwargs["stdout"]
    except KeyError:
        kwargs["stdout"] = subprocess.PIPE

    if kwargs.get("stderr") is None:
        kwargs["stderr"] = subprocess.PIPE
    if kwargs.get("check") is None:
        kwargs["check"] = True

    try:
        sub = subprocess.run(list_args, **kwargs)
    except (FileNotFoundError, TypeError) as e:
        logging.debug("arguments to subprocess")
        logging.debug(list_args)
        logging.debug(msg)
        logging.debug(kwargs)
        raise Exception("Command not found") from e
    except subprocess.CalledProcessError as e:
        if e.stdout is not None:
            logging.debug("stdout: \n{}".format(e.stdout.decode()))
        if e.stderr is not None:
            logging.debug("stderr: \n{}".format(e.stderr.decode()))
        logging.debug("returncode: {}".format(e.returncode))
        if reraise:
            raise Exception(msg) from e
        else:
            logging.warning(msg)
            logging.debug(traceback.format_exc())
            return None
    return sub
