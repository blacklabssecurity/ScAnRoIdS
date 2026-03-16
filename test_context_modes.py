#!/usr/bin/env python3
"""
Test Harness for ScanContext: New Session vs. Adopt Mode

To test: sudo python3 test_context_modes.py

"""
import os
import shutil
from core.context import ScanContext
from core.ui import log_success, log_note, log_task

def run_test():
    customer = "TestCustomer"
    
    # --- TEST 1: NEW SESSION ---
    log_task("--- RUNNING TEST 1: NEW SESSION ---")
    ctx_new = ScanContext(customer)
    
    print(f"[>] Created Folder: {ctx_new.base_path}")
    print(f"[>] Captured Date: {ctx_new.date_str} | Time: {ctx_new.time_str}")

    # --- TEST 2: ADOPT SESSION ---
    log_task("\n--- RUNNING TEST 2: ADOPT MODE ---")
    # Simulate a tool restart by passing the path of the folder we just made
    ctx_adopt = ScanContext(customer, resume_path=str(ctx_new.base_path))
    
    print(f"[>] Adopted Folder: {ctx_adopt.base_path}")
    # These should match Test 1 exactly, proving it parsed the folder name
    print(f"[>] Extracted Date: {ctx_adopt.date_str} | Time: {ctx_adopt.time_str}")

    # Check if sub-dirs are mapped correctly
    if ctx_adopt.dirs['artifacts'].exists():
        log_success("Internal directory mapping confirmed for Adopted Session.")

    # Optional Cleanup: Uncomment to delete the test folders after success
    # shutil.rmtree(ctx_new.base_path)
    # log_note("Cleanup complete.")

if __name__ == "__main__":
    run_test()
