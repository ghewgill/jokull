import pprint
import shutil
import sys

import libjokull

def do_create(out, session, args):
    session.create_vault(args[2])

def do_delete(out, session, args):
    if len(args) >= 4:
        session.delete_archive(args[2], args[3])
    else:
        session.delete_vault(args[2])

def do_describe(out, session, args):
    vault = session.describe_vault(args[2])
    pprint.pprint(vault, stream=out)

def do_get(out, session, args):
    f = session.get(args[2], args[3])
    with open(args[4], "wb") as outf:
        shutil.copyfileobj(f, outf)

def do_jobs(out, session, args):
    jobs = session.list_jobs(args[2])
    pprint.pprint(jobs, stream=out)

def do_request(out, session, args):
    if len(args) >= 4:
        r = session.new_job(args[2], archive_id=args[3])
    else:
        r = session.new_job(args[2])
    print(r, file=out)

def do_upload(out, session, args):
    with open(args[3], "rb") as f:
        r = session.upload_archive(args[2], f, filename=args[3])
        print(r, file=out)

def do_vaults(out, session, args):
    vaults = session.list_vaults()
    pprint.pprint(vaults, stream=out)

Commands = {
    "create": do_create,
    "delete": do_delete,
    "describe": do_describe,
    "get": do_get,
    "jobs": do_jobs,
    "request": do_request,
    "upload": do_upload,
    "vaults": do_vaults,
}

def main():
    fn = Commands.get(sys.argv[1])
    if fn is None:
        print("Unknown command: {}".format(sys.argv[1]))
        sys.exit(1)
    session = libjokull.Jokull()
    fn(sys.stdout, session, sys.argv)

if __name__ == "__main__":
    main()
