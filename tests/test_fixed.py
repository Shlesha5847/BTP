

from cpabe.fixed.scheme import SensorsCPABEFixedIDBound
from tests.test_common import run_common_test

if __name__ == "__main__":
    scheme = SensorsCPABEFixedIDBound()
    run_common_test(scheme, is_fixed=True)
