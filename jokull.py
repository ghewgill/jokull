import pprint
import shutil
import sys

import libjokull

def do_create(session, args):
    session.create_vault(args[2])

def do_delete(session, args):
    if len(args) >= 4:
        session.delete_archive(args[2], args[3])
    else:
        session.delete_vault(args[2])

def do_get(session, args):
    f = session.get(args[2], args[3])
    with open(args[4], "wb") as outf:
        shutil.copyfileobj(f, outf)

def do_jobs(session, args):
    jobs = session.list_jobs(args[2])
    pprint.pprint(jobs)

def do_request(session, args):
    if len(args) >= 4:
        r = session.new_job(args[2], archive_id=args[3])
    else:
        r = session.new_job(args[2])
    print(r)

def do_upload(session, args):
    with open(args[3], "rb") as f:
        r = session.upload_archive(args[2], f)
        print(r)

def do_vaults(session, args):
    vaults = session.list_vaults()
    pprint.pprint(vaults)

Commands = {
    "create": do_create,
    "delete": do_delete,
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
    fn(session, sys.argv)

if __name__ == "__main__":
    main()
