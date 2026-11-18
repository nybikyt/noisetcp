#!/usr/bin/env python3
"""Accept-and-close TCP listener for targets with `tcp_syncookies=2`.

noisytcp switches to TIME_WAIT mode automatically when it detects that the
target answers every SYN with a cookie.  Such a target must accept the
completed connection and close it immediately, which is exactly the state the
TIME_WAIT choreography expects.

    python3 lab/close-listener.py --port 9000

Lab use only: run it on the target you own.
"""

import argparse
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="0.0.0.0", help="address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="TCP port (default: 9000)")
    parser.add_argument("--backlog", type=int, default=4096, help="listen backlog (default: 4096)")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.backlog < 1:
        parser.error("--backlog must be positive")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(args.backlog)
    print(
        f"close-listener: {args.bind}:{args.port} backlog={args.backlog}; "
        "every accepted connection is closed immediately",
        flush=True,
    )
    try:
        while True:
            connection, peer = listener.accept()
            connection.close()
            print(f"accepted {peer[0]}:{peer[1]} and closed", flush=True)
    except KeyboardInterrupt:
        print("close-listener: stopped", flush=True)
        return 0
    except OSError as error:
        print(f"close-listener: {error}", file=sys.stderr)
        return 1
    finally:
        listener.close()


if __name__ == "__main__":
    sys.exit(main())
