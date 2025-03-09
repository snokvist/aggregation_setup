#!/usr/bin/env python3
import argparse
import subprocess
import re
import logging
import sys
import os
import signal

CONFIG_FILE = "/etc/wifibroadcast.cfg"
SSH_TIMEOUT = 5  # seconds

def extract_nodes_block(content):
    """
    Extract the entire nodes block from the config file.
    It finds the line where nodes = { starts and then uses brace counting
    to return everything inside the outermost { }.
    """
    match = re.search(r'nodes\s*=\s*\{', content)
    if not match:
        logging.error("Could not find 'nodes' block in config file.")
        sys.exit(1)
    
    start_index = match.end()  # position just after the opening '{'
    brace_count = 1
    i = start_index
    while i < len(content) and brace_count > 0:
        if content[i] == '{':
            brace_count += 1
        elif content[i] == '}':
            brace_count -= 1
        i += 1

    if brace_count != 0:
        logging.error("Braces in 'nodes' block are not balanced.")
        sys.exit(1)
    
    # Return the content inside the outermost { }
    return content[start_index:i-1]

def parse_nodes(filename=CONFIG_FILE):
    """
    Parse the config file to extract node IP addresses from the nodes keys.
    This function extracts the nodes block and then uses a regex that only matches
    quoted IP addresses immediately followed by a colon.
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read config file {filename}: {e}")
        sys.exit(1)

    nodes_block = extract_nodes_block(content)
    ips = re.findall(r"['\"]((?:\d{1,3}\.){3}\d{1,3})['\"]\s*:", nodes_block)
    if not ips:
        logging.error("No valid IP addresses found in the nodes configuration.")
    else:
        logging.info(f"Found IP addresses: {ips}")
    return ips

def run_command(ip, command, is_local=False):
    """
    Run the given command either locally or remotely over SSH.
    For remote (SSH) commands, a 5 second timeout is applied.
    If the command does not complete in time, the process group is killed.
    Returns a subprocess.CompletedProcess instance.
    """
    try:
        if is_local:
            logging.info(f"Running local command on {ip}: {command}")
            # For local commands we don't need a separate process group.
            proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        else:
            ssh_command = f"ssh root@{ip} '{command}'"
            logging.info(f"Running remote command on {ip}: {ssh_command}")
            # Start the SSH command in its own process group.
            proc = subprocess.Popen(ssh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        
        try:
            stdout, stderr = proc.communicate(timeout=SSH_TIMEOUT)
            return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            logging.error(f"Command on {ip} timed out after {SSH_TIMEOUT} seconds.")
            # If remote, kill the entire process group; otherwise kill the process.
            if not is_local:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    logging.info(f"Killed process group for command on {ip}.")
                except Exception as kill_exception:
                    logging.error(f"Failed to kill process group for command on {ip}: {kill_exception}")
            proc.kill()  # Ensure the process is terminated.
            stdout, stderr = proc.communicate()
            return subprocess.CompletedProcess(proc.args, 1, stdout, f"Timeout after {SSH_TIMEOUT} seconds: {stderr}")
    except Exception as e:
        logging.error(f"Error running command on {ip}: {e}")
        return subprocess.CompletedProcess(command, 1, "", str(e))

def cleanup():
    """
    Cleanup actions on exit (for example, closing connections, removing temporary files, etc.)
    Add your extra cleanup code here.
    """
    logging.info("Performing cleanup actions...")

def main():
    parser = argparse.ArgumentParser(
        description="Script to change the wireless channel on nodes based on /etc/wifibroadcast.cfg"
    )
    parser.add_argument("channel", type=int, help="Channel to set")
    parser.add_argument("bandwidth", type=str, help="Bandwidth to set (e.g., 20, HT20, HT40+, HT40-)")
    parser.add_argument("region", type=str, help="Region to set")
    parser.add_argument("--handle-local-separately", action="store_true",
                        help="If set, handle 127.0.0.1 (local node) with special logic")
    args = parser.parse_args()

    command = f"/usr/sbin/wfb-ng-change.sh {args.channel} {args.bandwidth} {args.region}"
    logging.info(f"Using command: {command}")

    ips = parse_nodes()
    if not ips:
        logging.error("No nodes to process. Exiting.")
        sys.exit(1)

    success = {}
    errors = {}

    try:
        for ip in ips:
            if ip == "127.0.0.1":
                if args.handle_local_separately:
                    logging.info("Handling local node (127.0.0.1) with special logic.")
                    result = run_command(ip, command, is_local=True)
                else:
                    logging.info("Handling local node (127.0.0.1) as part of the loop.")
                    result = run_command(ip, command, is_local=True)
            else:
                result = run_command(ip, command, is_local=False)

            if result.returncode == 0:
                success[ip] = result.stdout.strip()
                logging.info(f"Command on {ip} succeeded: {result.stdout.strip()}")
            else:
                errors[ip] = result.stderr.strip()
                logging.error(f"Command on {ip} failed with error: {result.stderr.strip()}")
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Exiting gracefully...")
        cleanup()
        sys.exit(1)

    # Print summary.
    print("\n=== Summary ===")
    print("Success:")
    if success:
        for ip, out in success.items():
            print(f"  {ip}: {out}")
    else:
        print("  None")

    print("\nErrors:")
    if errors:
        for ip, err in errors.items():
            print(f"  {ip}: {err}")
    else:
        print("  None")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    try:
        main()
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received in main. Exiting gracefully...")
        cleanup()
        sys.exit(1)
