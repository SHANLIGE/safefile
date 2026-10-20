# Lets you run it as `python -m safefile ...` without installing the script.
import sys

from .cli import main

sys.exit(main())
