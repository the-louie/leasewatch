"""Entry point: collector thread + web server. `python -m leasewatch`."""
from __future__ import annotations

import logging
import os
import signal
import sqlite3
import sys
import threading

from . import __version__
from .collector import Collector
from .config import Config
from .db import Database
from .web import serve


def main() -> int:
    level = (os.environ.get("LOG_LEVEL") or "INFO").strip().upper()
    known = isinstance(logging.getLevelName(level), int)
    logging.basicConfig(level=level if known else "INFO", format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("leasewatch")
    if not known:
        log.warning("LOG_LEVEL=%r is not a log level, using INFO", level)
    cfg = Config()
    problems = cfg.validate()
    if problems:
        for p in problems:
            log.error("config: %s", p)
        return 2
    try:
        os.makedirs(cfg.data_dir, exist_ok=True)
        db = Database(cfg.db_path)
    except (OSError, sqlite3.Error) as e:
        log.error("cannot open %s: %s", cfg.db_path, e)
        return 2
    stop = threading.Event()
    collector = Collector(cfg, db)
    t = threading.Thread(target=collector.loop, args=(stop,), name="collector", daemon=True)
    try:
        srv = serve(cfg, db, __version__)
    except OSError as e:
        log.error("cannot listen on %s:%d: %s", cfg.listen_host, cfg.listen_port, e)
        return 2
    t.start()  # only once the port is ours: a failed bind must not leave a poller running (and mailing) without a UI

    def shutdown(*_):
        log.info("shutting down")
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log.info("leasewatch %s, polling %s every %ss, mail %s", __version__, cfg.fw1_url, cfg.poll_seconds, "on" if cfg.mail_enabled else "off")
    srv.serve_forever()
    srv.server_close()
    t.join(10)  # let a poll in flight commit before the interpreter goes away
    return 0


if __name__ == "__main__":
    sys.exit(main())
