# main.py
# ================================================================
# Entry point for running CP-ABE tests
# You can choose which scheme to test:
#   1) Vulnerable CP-ABE (collusion-possible)
#   2) Secure CP-ABE (identity-bound & collusion-resistant)
# ================================================================

from tests.test_common import run_common_test

# Import both schemes
from cpabe.flawed.scheme import CollusionFlawedCPABE
from cpabe.fixed.scheme import SensorsCPABEFixedIDBound


def main():
    print("\n====================== CP-ABE DEMO ======================\n")

    # ------------------------------------------------------------------
    # 1) Test the vulnerable (flawed) attribute-only CP-ABE
    # ------------------------------------------------------------------
    print("\n\n====================================================")
    print("RUNNING TEST FOR VULNERABLE SCHEME (COLLUSION-POSSIBLE)")
    print("====================================================")

    vulnerable_scheme = CollusionFlawedCPABE()
    run_common_test(vulnerable_scheme, is_fixed=False)

    # ------------------------------------------------------------------
    # 2) Test the secure (fixed) identity-bound CP-ABE
    # ------------------------------------------------------------------
    print("\n\n====================================================")
    print("RUNNING TEST FOR SECURE SCHEME (COLLUSION-RESISTANT)")
    print("====================================================")

    secure_scheme = SensorsCPABEFixedIDBound()
    run_common_test(secure_scheme, is_fixed=True)

    print("\n===================== END OF DEMO =====================\n")


if __name__ == "__main__":
    main()
