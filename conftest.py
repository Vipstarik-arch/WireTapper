"""Make the flat WireTapper modules importable from anywhere in the test run."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
