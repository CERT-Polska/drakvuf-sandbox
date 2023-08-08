@click.group(help="Manage VM raw memory pre-sample dumps")
def memdump():
    pass


@memdump.command(name="export", help="Upload pre-sample raw memory dump to MinIO.")
@click.option("--instance", required=True, type=int, help="Instance ID of restored VM")
@click.option(
    "--bucket",
    default="presample-memdumps",
    help="MinIO bucket to store the compressed raw image",
)
def memdump_export(bucket, instance):
    install_info = InstallInfo.try_load()
    if install_info is None:
        logging.error(
            "Missing installation info. Did you forget to set up the sandbox?"
        )
        return

    backend = get_storage_backend(install_info)
    vm = VirtualMachine(backend, instance)
    if vm.is_running:
        logging.exception(f"vm-{instance} is running")
        return

    logging.info("Calculating snapshot hash...")
    snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))
    name = f"{snapshot_sha256}_pre_sample.raw_memdump.gz"

    mc = get_minio_client(conf)

    if not mc.bucket_exists(bucket):
        logging.error("Bucket %s doesn't exist", bucket)
        return

    try:
        mc.stat_object(bucket, name)
        logging.info("This file already exists in specified bucket")
        return
    except NoSuchKey:
        pass
    except Exception:
        logging.exception("Failed to check if object exists on minio")

    logging.info("Restoring VM and performing memory dump")

    try:
        vm.restore(pause=True)
    except subprocess.CalledProcessError:
        logging.exception(f"Failed to restore VM {vm.vm_name}")
        with open(f"/var/log/xen/qemu-dm-{vm.vm_name}.log", "rb") as f:
            logging.error(f.read())
    logging.info("VM restored")

    with tempfile.NamedTemporaryFile() as compressed_memdump:
        vm.memory_dump(compressed_memdump.name)

        logging.info(f"Uploading {name} to {bucket}")
        mc.fput_object(bucket, name, compressed_memdump.name)

    try:
        vm.destroy()
    except Exception:
        logging.exception("Failed to destroy VM")

    logging.info("Done")
