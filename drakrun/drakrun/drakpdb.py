import argparse

from drakrun.lib.drakpdb import fetch_pdb, make_pdb_profile, pe_codeview_data


def main():
    parser = argparse.ArgumentParser(description="drakpdb")
    parser.add_argument(
        "action",
        type=str,
        help="one of: fetch_pdb (requires --pdb-name and --guid_age), parse_pdb (requires --pdb-name), pe_codeview_data (requires --file)",
    )
    parser.add_argument(
        "--pdb_name",
        type=str,
        help="name of pdb file with extension, e.g. ntkrnlmp.pdb",
    )
    parser.add_argument("--guid_age", type=str, help="guid/age of the pdb file")
    parser.add_argument(
        "--file", type=str, help="file to get symstore_hash (GUID + Age) from"
    )

    args = parser.parse_args()

    if args.action == "parse_pdb":
        print(make_pdb_profile(args.pdb_name))
    elif args.action == "fetch_pdb":
        fetch_pdb(args.pdb_name, args.guid_age)
    elif args.action == "pe_codeview_data":
        print(pe_codeview_data(args.file))
    else:
        raise RuntimeError("Unknown action")


if __name__ == "__main__":
    main()
