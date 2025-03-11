#!/usr/bin/env python3
import argparse
import subprocess
import re
import logging
import sys
import os
import signal

# --- Configuration Constants ---
CONFIG_FILE = "/etc/wifibroadcast.cfg"
DEFAULTS_FILE = "/usr/sbin/wfb-ng.sh"  # file holding default values to update/restore
CHANGE_CMD_FILE = "/usr/sbin/wfb-ng-change.sh"  # command to run on nodes
SSH_TIMEOUT = 10  # seconds

# Approved channel combinations
APPROVED_CHANNELS = {
    "HT20": [140, 161, 165],
    "HT40+": [161],
    "HT40-": [161]
}

# Predetermined restore settings (used if killswitch cancellation fails)
RESTORE_CHANNEL = 165
RESTORE_BANDWIDTH = "HT20"
RESTORE_REGION = "00"

# --- Utility Functions ---

def read_defaults(filename=DEFAULTS_FILE):
    """
    Read and return the current default values from the given file.
    Returns a tuple (default_channel, default_bandwidth, default_region).
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

def restore_defaults(new_channel, new_bandwidth, new_region, filename=DEFAULTS_FILE):
    """
    Restore the default values in the given file to the specified settings.
    (This function is used both for normal restore and for predetermined restore.)
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {filename} for restore: {e}")
        return False
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
        logging.error(f"Failed to write restored defaults to {filename}: {e}")
        return False
    logging.info("Restored default values successfully.")
    return True

def get_server_address(filename=CONFIG_FILE):
    """
    Extract the server_address value from the config file.
    Expects a line like: server_address = '192.169.1.49'
    """
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Failed to read {filename} for server_address: {e}")
        sys.exit(1)
    match = re.search(r'^\s*server_address\s*=\s*[\'"]([^\'"]+)[\'"]', content, re.MULTILINE)
    if not match:
        logging.error("Failed to extract server_address from the config file.")
        sys.exit(1)
    return match.group(1)

def extract_nodes_block(content):
    """
    Extract the entire nodes block from the config file.
    """
    match = re.search(r'nodes\s*=\s*\{', content)
    if not match:
        logging.error("Could not find 'nodes' block in config file.")
        sys.exit(1)
    start_index = match.end()
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
    logging.info("Performing cleanup actions...")

# --- Main Program ---

def main():
    if os.geteuid() != 0:
        logging.error("This program must be run as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Script to change the wireless channel on nodes based on /etc/wifibroadcast.cfg"
    )
    parser.add_argument("channel", type=int, help="Channel to set")
    parser.add_argument("bandwidth", type=str, help="Bandwidth to set (e.g., HT20, HT40+, HT40-)")
    parser.add_argument("region", type=str, help="Region to set")
    parser.add_argument("--handle-local-separately", action="store_true",
                        help="If set, handle 127.0.0.1 with special logic")
    parser.add_argument("--sync-vtx", action="store_true",
                        help="If set, sync VTX by sending '/usr/bin/sync_channel.sh <channel> <bandwidth> <region>' to root@10.5.0.10")
    args = parser.parse_args()

    # --- Approved Channel Validation ---
    approved = APPROVED_CHANNELS
    if args.bandwidth not in approved or args.channel not in approved[args.bandwidth]:
        print("Error: The channel/bandwidth combination you provided is not approved.")
        print("Approved channel/bandwidth combinations:")
        for bw, ch_list in approved.items():
            print(f"  {bw}: {', '.join(str(ch) for ch in ch_list)}")
        sys.exit(1)

    # Read original default values.
    orig_channel, orig_bandwidth, orig_region = read_defaults()
    logging.info(f"Original defaults: CHANNEL={orig_channel}, BANDWIDTH={orig_bandwidth}, REGION={orig_region}")

    # Update defaults file with new values.
    update_defaults(args.channel, args.bandwidth, args.region)

    # Build command strings.
    command_local = f"{CHANGE_CMD_FILE} {args.channel} {args.bandwidth} {args.region}"
    server_address = get_server_address()
    command_remote = f"{CHANGE_CMD_FILE} {args.channel} {args.bandwidth} {args.region} {server_address}"
    logging.info(f"Local command: {command_local}")
    logging.info(f"Remote command: {command_remote}")

    # Sync VTX if requested.
    if args.sync_vtx:
        sync_command = (f'nohup /usr/bin/sync_channel.sh {args.channel} {args.bandwidth} {args.region} '
                        f'> /dev/null 2>&1 & echo "SYNC_STARTED"; exit')
        logging.info(f"Syncing VTX by running command on 10.5.0.10: {sync_command}")
        result = run_command("10.5.0.10", sync_command, is_local=False)
        if result.returncode != 0 or "SYNC_STARTED" not in result.stdout:
            logging.error(f"Sync VTX command failed on 10.5.0.10 with output: {result.stdout.strip()} and error: {result.stderr.strip()}")
            logging.error("Restoring default values due to sync failure...")
            restore_defaults(orig_channel, orig_bandwidth, orig_region)
            sys.exit(1)
        else:
            logging.info(f"Sync VTX command succeeded with output: {result.stdout.strip()}")

    # Parse node IP addresses.
    ips = parse_nodes()
    if not ips:
        logging.error("No nodes to process. Exiting.")
        sys.exit(1)
    local_ips = [ip for ip in ips if ip == "127.0.0.1"]
    remote_ips = [ip for ip in ips if ip != "127.0.0.1"]

    success = {}
    errors = {}

    # Process local nodes.
    try:
        for ip in local_ips:
            if args.handle_local_separately:
                logging.info("Handling local node (127.0.0.1) with special logic.")
            else:
                logging.info("Handling local node (127.0.0.1) as part of the loop.")
            result = run_command(ip, command_local, is_local=True)
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

    # Process remote nodes.
    try:
        for ip in remote_ips:
            result = run_command(ip, command_remote, is_local=False)
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

    # After processing all nodes, if --sync-vtx is requested, kill the killswitch.
    if args.sync_vtx:
        kill_command = "killall killswitch.sh && echo 'KILLSWITCH_KILLED'; exit"
        logging.info("Killing killswitch on VTX by running command: " + kill_command)
        result_kill = run_command("10.5.0.10", kill_command, is_local=False)
        if result_kill.returncode != 0 or "KILLSWITCH_KILLED" not in result_kill.stdout:
            logging.error(f"Failed to kill killswitch on VTX. Output: {result_kill.stdout.strip()} Error: {result_kill.stderr.strip()}")
            logging.error("Restoring predetermined settings due to killswitch kill failure...")

            # Restore predetermined settings locally.
            restore_defaults(RESTORE_CHANNEL, RESTORE_BANDWIDTH, RESTORE_REGION)
            local_restore_command = f"{CHANGE_CMD_FILE} {RESTORE_CHANNEL} {RESTORE_BANDWIDTH} {RESTORE_REGION}"
            logging.info(f"Restoring settings on local node 127.0.0.1 with command: {local_restore_command}")
            result_local_restore = run_command("127.0.0.1", local_restore_command, is_local=True)
            if result_local_restore.returncode != 0:
                logging.error(f"Failed to restore settings on local node 127.0.0.1: {result_local_restore.stderr.strip()}")
            else:
                logging.info(f"Settings restored on local node 127.0.0.1: {result_local_restore.stdout.strip()}")

            # Restore predetermined settings on remote nodes.
            remote_restore_command = f"{CHANGE_CMD_FILE} {RESTORE_CHANNEL} {RESTORE_BANDWIDTH} {RESTORE_REGION} {server_address}"
            for ip in remote_ips:
                logging.info(f"Restoring settings on remote node {ip} with command: {remote_restore_command}")
                result_restore = run_command(ip, remote_restore_command, is_local=False)
                if result_restore.returncode != 0:
                    logging.error(f"Failed to restore settings on remote node {ip}: {result_restore.stderr.strip()}")
                else:
                    logging.info(f"Settings restored on remote node {ip}: {result_restore.stdout.strip()}")
            sys.exit(1)
        else:
            logging.info("Successfully killed killswitch on VTX.")

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
