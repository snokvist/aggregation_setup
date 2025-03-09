#!/usr/bin/env python3
import argparse
import subprocess
import re
import logging
import sys
import os
import signal

CONFIG_FILE = "/etc/wifibroadcast.cfg"
# The file that holds default values (to be updated and restored if needed)
DEFAULTS_FILE = "/usr/sbin/wfb-ng.sh"
# The command file that is executed on nodes
CHANGE_CMD_FILE = "/usr/sbin/wfb-ng-change.sh"
SSH_TIMEOUT = 5  # seconds

def read_defaults(filename=DEFAULTS_FILE):
    """
    Read and return the current default values from the given file.
    Returns a tuple (default_channel, default_bandwidth, default_region).
    The regexes allow for optional leading whitespace.
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {filename}: {e}")
        sys.exit(1)

    channel_match = re.search(r'^\s*DEFAULT_CHANNEL\s*=\s*(\S+)', content, re.MULTILINE)
    bandwidth_match = re.search(r'^\s*DEFAULT_BANDWIDTH\s*=\s*"?([^"\n]+)"?', content, re.MULTILINE)
    region_match = re.search(r'^\s*DEFAULT_REGION\s*=\s*"?([^"\n]+)"?', content, re.MULTILINE)

    if not (channel_match and bandwidth_match and region_match):
        logging.error("Failed to extract default values from the script file.")
        sys.exit(1)

    return channel_match.group(1), bandwidth_match.group(1), region_match.group(1)

def update_defaults(new_channel, new_bandwidth, new_region, filename=DEFAULTS_FILE):
    """
    Update the default values in the given file to the new values.
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {filename} for update: {e}")
        sys.exit(1)

    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_CHANNEL\s*=\s*).*$',
                         r'\g<prefix>' + str(new_channel),
                         content, flags=re.MULTILINE)
    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_BANDWIDTH\s*=\s*).*$',
                         r'\g<prefix>"' + new_bandwidth + '"',
                         content_new, flags=re.MULTILINE)
    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_REGION\s*=\s*).*$',
                         r'\g<prefix>"' + new_region + '"',
                         content_new, flags=re.MULTILINE)
    try:
        with open(filename, 'w') as f:
            f.write(content_new)
    except Exception as e:
        logging.error(f"Failed to write updated defaults to {filename}: {e}")
        sys.exit(1)
    logging.info("Default values updated successfully.")

def restore_defaults(orig_channel, orig_bandwidth, orig_region, filename=DEFAULTS_FILE):
    """
    Restore the default values in the given file to the original values.
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {filename} for restore: {e}")
        return False

    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_CHANNEL\s*=\s*).*$',
                         r'\g<prefix>' + str(orig_channel),
                         content, flags=re.MULTILINE)
    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_BANDWIDTH\s*=\s*).*$',
                         r'\g<prefix>"' + orig_bandwidth + '"',
                         content_new, flags=re.MULTILINE)
    content_new = re.sub(r'^(?P<prefix>\s*DEFAULT_REGION\s*=\s*).*$',
                         r'\g<prefix>"' + orig_region + '"',
                         content_new, flags=re.MULTILINE)
    try:
        with open(filename, 'w') as f:
            f.write(content_new)
    except Exception as e:
        logging.error(f"Failed to write restored defaults to {filename}: {e}")
        return False

    logging.info("Restored default values successfully.")
    return True

def extract_nodes_block(content):
    """
    Extract the entire nodes block from the config file.
    It finds the line where 'nodes = {' starts and then uses brace counting
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
    
    return content[start_index:i-1]

def parse_nodes(filename=CONFIG_FILE):
    """
    Parse the config file to extract node IP addresses from the nodes keys.
    This function extracts the nodes block and uses a regex that matches
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
    Run the given command either locally or remotely (via SSH).
    For remote commands, a timeout is applied and if exceeded the entire
    process group is killed.
    Returns a subprocess.CompletedProcess instance.
    """
    try:
        if is_local:
            logging.info(f"Running local command on {ip}: {command}")
            proc = subprocess.Popen(command, shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
        else:
            ssh_command = f"ssh root@{ip} '{command}'"
            logging.info(f"Running remote command on {ip}: {ssh_command}")
            proc = subprocess.Popen(ssh_command, shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, preexec_fn=os.setsid)
        
        try:
            stdout, stderr = proc.communicate(timeout=SSH_TIMEOUT)
            return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            logging.error(f"Command on {ip} timed out after {SSH_TIMEOUT} seconds.")
            if not is_local:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    logging.info(f"Killed process group for command on {ip}.")
                except Exception as kill_exception:
                    logging.error(f"Failed to kill process group for command on {ip}: {kill_exception}")
            proc.kill()
            stdout, stderr = proc.communicate()
            return subprocess.CompletedProcess(proc.args, 1, stdout, f"Timeout after {SSH_TIMEOUT} seconds: {stderr}")
    except Exception as e:
        logging.error(f"Error running command on {ip}: {e}")
        return subprocess.CompletedProcess(command, 1, "", str(e))

def cleanup():
    """
    Cleanup actions on exit (for example, closing connections, removing temporary files, etc.)
    """
    logging.info("Performing cleanup actions...")

def main():
    # Require running as root.
    if os.geteuid() != 0:
        logging.error("This program must be run as root.")
        sys.exit(1)

    # Parse command-line arguments.
    parser = argparse.ArgumentParser(
        description="Script to change the wireless channel on nodes based on /etc/wifibroadcast.cfg"
    )
    parser.add_argument("channel", type=int, help="Channel to set")
    parser.add_argument("bandwidth", type=str, help="Bandwidth to set (e.g., 20, HT20, HT40+, HT40-)")
    parser.add_argument("region", type=str, help="Region to set")
    parser.add_argument("--handle-local-separately", action="store_true",
                        help="If set, handle 127.0.0.1 (local node) with special logic")
    parser.add_argument("--sync-vtx", action="store_true",
                        help="If set, sync VTX by sending '/usr/bin/sync_channel.sh <channel> <bandwidth> <region>' to root@10.5.0.10")
    args = parser.parse_args()

    # Read original default values from the defaults file.
    orig_channel, orig_bandwidth, orig_region = read_defaults()
    logging.info(f"Original defaults: CHANNEL={orig_channel}, BANDWIDTH={orig_bandwidth}, REGION={orig_region}")

    # Update the defaults file with the new values.
    update_defaults(args.channel, args.bandwidth, args.region)

    # Build the command that will be executed on each node.
    command = f"{CHANGE_CMD_FILE} {args.channel} {args.bandwidth} {args.region}"
    logging.info(f"Using command: {command}")

    # Parse node IP addresses from the configuration file.
    ips = parse_nodes()
    if not ips:
        logging.error("No nodes to process. Exiting.")
        sys.exit(1)

    # Process local nodes first.
    local_ips = [ip for ip in ips if ip == "127.0.0.1"]
    remote_ips = [ip for ip in ips if ip != "127.0.0.1"]

    success = {}
    errors = {}

    try:
        for ip in local_ips:
            if args.handle_local_separately:
                logging.info("Handling local node (127.0.0.1) with special logic.")
            else:
                logging.info("Handling local node (127.0.0.1) as part of the loop.")
            result = run_command(ip, command, is_local=True)
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

    # If --sync-vtx is requested, run the sync command on host 10.5.0.10.
    if args.sync_vtx:
        sync_command = f"/usr/bin/sync_channel.sh {args.channel} {args.bandwidth} {args.region}"
        logging.info(f"Syncing VTX by running command on 10.5.0.10: {sync_command}")
        result = run_command("10.5.0.10", sync_command, is_local=False)
        if result.returncode != 0:
            logging.error(f"Sync VTX command failed on 10.5.0.10 with error: {result.stderr.strip()}")
            logging.error("Restoring default values due to sync failure...")
            restore_defaults(orig_channel, orig_bandwidth, orig_region)
            sys.exit(1)
        else:
            logging.info(f"Sync VTX command succeeded: {result.stdout.strip()}")

    # Process remote nodes.
    try:
        for ip in remote_ips:
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
