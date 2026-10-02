#!/usr/bin/env python
import sys

if "--start-screenshot-worker" in sys.argv[1:]:
    # Sandboxed worker: start without the app bootstrap (Settings/.env, DB, SMTP)
    from src.screenshot_worker import main as screenshot_worker_main

    screenshot_worker_main()
else:
    from src import main

    main.main()
