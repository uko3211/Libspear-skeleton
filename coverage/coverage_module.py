import os
import sys

class CovChecker:
    def __init__(self, TARGET_DIR):
        self.TARGET_DIR = TARGET_DIR

    def js_file_path(self):
        target_check_result = []

        for dirpath, dirnames, filenames in os.walk(self.TARGET_DIR):
            for f in filenames:
                file_full_path = os.path.join(dirpath, f)
                if file_full_path.endswith(".js") or file_full_path.endswith(".ts"):
                    target_check_result.append(file_full_path)
                    
        return target_check_result