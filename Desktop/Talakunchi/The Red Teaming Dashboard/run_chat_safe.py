"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    RUN CHAT SAFE - Streamlit Launcher                        ║
║                    Red Teaming Dashboard - run_chat_safe.py                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This script is a safe launcher for the Streamlit chat application.         ║
║                                                                              ║
║  PURPOSE:                                                                    ║
║  - Launches chat.py using Streamlit                                         ║
║  - Disables file watcher to prevent PyTorch/ML model conflicts              ║
║  - Runs in headless mode (no browser auto-open on servers)                  ║
║                                                                              ║
║  WHY THIS FILE EXISTS:                                                       ║
║  When running Streamlit with ML models (like those in llm_guard),           ║
║  the default file watcher can cause conflicts with PyTorch's                ║
║  multiprocessing. This launcher disables that watcher.                      ║
║                                                                              ║
║  USAGE:                                                                      ║
║  python run_chat_safe.py                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ============================================================================
# IMPORTS
# ============================================================================

# os: Operating system interface
# Used to set environment variables that configure Streamlit behavior
import os

# sys: System-specific parameters and functions
# Used to modify command-line arguments (sys.argv) and exit the script
import sys

# streamlit.web.cli: Streamlit's command-line interface module
# Provides the main() function that starts the Streamlit server
# We import it as 'stcli' for shorter reference
from streamlit.web import cli as stcli

# ============================================================================
# MAIN EXECUTION BLOCK
# ============================================================================
# This block only runs when the script is executed directly (not imported)
# Example: python run_chat_safe.py  ← This runs the block
# Example: import run_chat_safe     ← This does NOT run the block

if __name__ == '__main__':
    
    # ────────────────────────────────────────────────────────────────────────
    # STEP 1: Configure Environment Variables
    # ────────────────────────────────────────────────────────────────────────
    # Environment variables are key-value pairs that configure application behavior
    # These must be set BEFORE Streamlit starts
    
    # STREAMLIT_SERVER_FILE_WATCHER_TYPE = "none"
    # ─────────────────────────────────────────
    # WHAT: Disables Streamlit's file watcher
    # 
    # WHY: By default, Streamlit watches for file changes and auto-reloads.
    # This conflicts with PyTorch (used by llm_guard ML models) because:
    #   1. PyTorch uses multiprocessing for model loading
    #   2. File watcher also uses multiprocessing
    #   3. Both try to fork the process → CRASH
    # 
    # EFFECT: You must manually refresh the browser to see code changes
    os.environ["STREAMLIT_SERVER_FILE_WATCHER_TYPE"] = "none"
    
    # STREAMLIT_SERVER_HEADLESS = "true"
    # ─────────────────────────────────────
    # WHAT: Runs Streamlit without auto-opening a browser
    # 
    # WHY: 
    #   - On servers (no GUI), auto-open would fail
    #   - On local machines, prevents unwanted browser windows
    #   - User can manually navigate to the URL
    # 
    # EFFECT: Streamlit prints the URL but doesn't open browser
    os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"
    
    # ────────────────────────────────────────────────────────────────────────
    # STEP 2: Configure Command-Line Arguments
    # ────────────────────────────────────────────────────────────────────────
    # sys.argv is a list containing the command-line arguments
    # By default: sys.argv = ["run_chat_safe.py"]
    # 
    # We override it to simulate running:
    #   streamlit run chat.py --server.port 8520
    #
    # BREAKDOWN:
    #   "streamlit"      - The program name (required by argparse)
    #   "run"            - Streamlit subcommand to run an app
    #   "chat.py"        - The Streamlit app file to run
    #   "--server.port"  - Flag to specify the port
    #   "8520"           - Port number (default is 8501)
    #
    # WHY PORT 8520?
    #   - Avoids conflicts if other Streamlit apps are running
    #   - Easy to remember: 8520 ≈ "85" + "20" (arbitrary choice)
    sys.argv = ["streamlit", "run", "chat.py", "--server.port", "8520"]
    
    # ────────────────────────────────────────────────────────────────────────
    # STEP 3: Print Startup Message
    # ────────────────────────────────────────────────────────────────────────
    # Inform the user that the app is starting
    # The emoji (🚀) makes it visually distinct in the terminal
    print("🚀 Auto-launching Secure Chat with File Watcher DISABLED...")
    
    # ────────────────────────────────────────────────────────────────────────
    # STEP 4: Launch Streamlit
    # ────────────────────────────────────────────────────────────────────────
    # stcli.main() is the entry point for Streamlit's CLI
    # It reads sys.argv and starts the Streamlit server
    #
    # sys.exit() wraps the call to:
    #   1. Pass the return code to the operating system
    #   2. Ensure clean script termination
    #
    # WHAT HAPPENS:
    #   1. Streamlit reads sys.argv → ["streamlit", "run", "chat.py", ...]
    #   2. Starts HTTP server on port 8520
    #   3. Loads and runs chat.py
    #   4. Prints URL: http://localhost:8520
    #   5. Waits for user connections
    #
    # RETURN VALUE:
    #   - 0 = Success (clean shutdown)
    #   - Non-zero = Error occurred
    sys.exit(stcli.main())
