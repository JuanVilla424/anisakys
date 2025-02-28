#!/usr/bin/env python
import sys
from src import main
from src import repopulate

if sys.argv[1:] == ["repopulate"]:
    repopulate.repopulate_asn_and_cloudflare()
else:
    main.main()
