#!/usr/bin/env python
import sys
from src import main
from src import repopulate

if sys.argv[1:] == ["repopulate"]:
    repopulate.populate_provider_email()
else:
    main.main()
