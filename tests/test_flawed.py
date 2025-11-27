

from cpabe.flawed.scheme import CollusionFlawedCPABE
from tests.test_common import run_common_test

if __name__ == "__main__":
    scheme = CollusionFlawedCPABE()
    run_common_test(scheme, is_fixed=False)
