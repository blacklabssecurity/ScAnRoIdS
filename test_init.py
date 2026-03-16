#!/usr/bin/env python3
"""
Temporary test harness to verify core/context.py logic.
"""
from core.context import ScanContext
from core.ui import log_note, log_success

def test_session():
    # 1. Simulate user input
    customer = "ACME Corp"
    log_note(f"Simulating session initialization for: {customer}")

    # 2. Attempt to initialize the context
    # This should trigger log_task and log_success from inside context.py
    ctx = ScanContext(customer)

    # 3. Verify the paths internally
    log_note(f"Verifying mapping for 'artifacts': {ctx.dirs['artifacts']}")
    
    # 4. Check if the physical directory actually exists on disk
    if ctx.base_path.exists():
        log_success("VERIFICATION PASSED: Root session directory exists.")
        
        # List the sub-dirs to ensure the tree is complete
        sub_dirs = [d.name for d in ctx.base_path.iterdir() if d.is_dir()]
        log_note(f"Sub-directories created: {', '.join(sub_dirs)}")
    else:
        print("\033[1;31m[!] VERIFICATION FAILED: Directory not found.\033[0m")

if __name__ == "__main__":
    test_session()
