#!/usr/bin/env python3
"""
Parse all blocks (A, B, F, H, Z) from ModSecurity audit logs, output ALL transactions to CSV.
"""
import sys
import os
import csv
import re
from pathlib import Path
from datetime import datetime, timezone
import argparse
import yaml
import ipaddress
import time
import threading
import psutil

def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def load_list_file(path):
    try:
        with open(path, 'r') as f:
            return set(x.strip() for x in f if x.strip() and not x.startswith('#'))
    except Exception:
        return set()

def is_valid_ip(ip):
    try:
        result = ipaddress.ip_address(ip)
        # Allow ALL IPv4 and IPv6 addresses, including private
        return True
    except Exception:
        return False

def is_whitelisted(ip, whitelist):
    return ip in whitelist

def is_section(line, letter):
    return re.match(rf'^\s*-+[A-Za-z0-9\-]+-+{letter}--\s*$', line.strip()) is not None

def parse_modsec_log(path):
    transactions = []
    curr = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if is_section(line, 'A'):
                if curr:
                    transactions.append(curr)
                    curr = []
            curr.append(line.rstrip('\n'))
        if curr:
            transactions.append(curr)
    return transactions

def parse_transaction(lines):
    section = {}
    block = None
    block_id = ''
    for line in lines:
        m = re.match(r'^\s*-+([A-Za-z0-9\-]+)-+([A-Z])--\s*$', line.strip())
        if m:
            block_id = m.group(1)
            block = m.group(2)
            section[block] = []
            continue
        if block:
            section[block].append(line)
    if not block_id:
        return None
    tx = {
        'tx_id': block_id,
        'timestamp': '',
        'client_ip': '',
        'x_forwarded_for': '',
        'host': '',
        'method': '',
        'url': '',
        'url_type': '',
        'response_code': '',
        'anomaly_score': 0,
        'severity': '',
        'rule_ids': '',
        'messages': '',
        'user_agent': '',
        'is_vm_scan': False,
        'confirmed_attack': False
    }
    a = section.get('A', [])
    for l in a:
        m = re.match(r'\[(.+?)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', l)
        if m:
            tx['timestamp'] = m.group(1)
            tx['client_ip'] = m.group(3)
            tx['host'] = m.group(5)
    b = section.get('B', [])
    for l in b:
        l = l.strip()
        m = re.match(r'([A-Z]{3,10})\s+([^\s]+)\s+HTTP/\d\.\d', l)
        if m:
            tx['method'] = m.group(1)
            tx['url'] = m.group(2)
            tx['url_type'] = detect_url_type(tx['url'])
            continue
        if l.lower().startswith('user-agent:'):
            tx['user_agent'] = l.split(':',1)[1].strip()
        if l.lower().startswith('host:'):
            tx['host'] = l.split(':',1)[1].strip()
        if l.lower().startswith('x-forwarded-for:'):
            tx['x_forwarded_for'] = l.split(':',1)[1].strip()
    f = section.get('F', [])
    for l in f:
        m = re.search(r'HTTP/\d\.\d\s+(\d{3})', l)
        if m:
            tx['response_code'] = m.group(1)
    h = section.get('H', [])
    hjoin = ' '.join(h)
    m = re.search(r'Total Score:\s*(\d+)', hjoin)
    if m:
        tx['anomaly_score'] = int(m.group(1))
    m = re.search(r'Severity:\s*(\w+)', hjoin)
    if m:
        tx['severity'] = m.group(1).lower()
    rule_ids = re.findall(r'id\s*"?(\d+)"?', hjoin)
    tx['rule_ids'] = ','.join(rule_ids) if rule_ids else ''
    messages = re.findall(r'msg\s*"([^"]+)"', hjoin)
    tx['messages'] = ';'.join(messages) if messages else ''
    if 'scanner' in tx['user_agent'].lower() or 'zgrab' in tx['user_agent'].lower():
        tx['is_vm_scan'] = True
    for k in tx:
        if tx[k] is None:
            tx[k] = ''
    return tx

def detect_url_type(url):
    if url.endswith('.cgi'):
        return 'CGI'
    if url.endswith('.asp'):
        return 'ASP'
    if url.endswith('.php'):
        return 'PHP'
    return 'OTHER'

def live_log_monitor(log_path, callback):
    """ Continuously monitor a log file for appended data, calling callback(blocks) on new full transactions """
    print(f"Live mode: Monitoring {log_path} for new transactions ...")
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        buffer = []
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if is_section(line, 'A'):
                if buffer:
                    callback(buffer)
                    buffer = []
            buffer.append(line.rstrip('\n'))
        # On exit, flush (for completeness)
        if buffer:
            callback(buffer)

def main():
    parser = argparse.ArgumentParser(description="Parse ALL blocks, output ALL transactions.")
    parser.add_argument('--config', type=str, help='Path to config.yml', required=False)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--test-sample', type=str, help='Specify a specific log')
    args = parser.parse_args()

    config_path = args.config or 'config.yml'
    config = load_yaml(config_path)
    anomaly_threshold = int(config.get('anomaly_threshold', 8))
    ip_whitelist_path = config.get('ip_whitelist', 'ipwhitelist')
    url_whitelist_path = config.get('url_whitelist', 'url_whitelist.txt')
    ip_whitelist = load_list_file(ip_whitelist_path)
    url_whitelist = load_list_file(url_whitelist_path)
    output_dir = Path(config.get('output_dir', 'output'))
    output_dir.mkdir(parents=True, exist_ok=True)
    today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    output_csv = output_dir / f"modsec_output_{today_str}.csv"
    FIELDNAMES = ['tx_id', 'timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type', 'response_code', 'anomaly_score', 'severity', 'rule_ids', 'messages', 'user_agent', 'is_vm_scan', 'confirmed_attack']
    
    def is_url_whitelisted(url, whitelist):
        # Direct full match; can extend to supports regex/glob if desired
        return url in whitelist

    def process_tx_and_output(lines, writer):
        tx = parse_transaction(lines)
        if tx:
            is_ip_white = is_whitelisted(tx['client_ip'], ip_whitelist)
            is_url_white = is_url_whitelisted(tx['url'], url_whitelist)
            tx['confirmed_attack'] = int(tx['anomaly_score']) >= anomaly_threshold and not (is_ip_white or is_url_white)
            # Strict row validation: only FIELDNAMES, all present, no extra keys, ensure type safety
            outrow = {name: '' for name in FIELDNAMES}  # Initialize all columns
            for name in FIELDNAMES:
                val = tx.get(name, '')
                if isinstance(val, bool):
                    val = 'True' if val else 'False'
                if val is None:
                    val = ''
                outrow[name] = str(val)
            # Optionally warn about extra columns
            extra_keys = [k for k in tx.keys() if k not in FIELDNAMES]
            if extra_keys:
                print(f"Warning: Skipping extra columns not in FIELDNAMES: {extra_keys}")
            writer.writerow(outrow)
            print(f"TX {tx['tx_id']} | IP: {tx['client_ip']} | Score {tx['anomaly_score']} | Attack: {tx['confirmed_attack']}")

    # Read config for log mode and path
    live_mode = config.get('live_mode', False)
    log_file = config.get('waf_log', "modsecurity_120825_PIDC_YI90FOLWB02.log")

    if live_mode:
        print(f"Live log tail mode. Watching log: {log_file}")
        with open(output_csv, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
            writer.writeheader()
            def callback(lines):
                process_tx_and_output(lines, writer)
            try:
                live_log_monitor(log_file, callback)
            except KeyboardInterrupt:
                print("Stopped live monitoring.")
        print(f"Report written to: {output_csv}")
    else:
        log_files = [args.test_sample] if args.test_sample else [log_file]
        print(f"Scanning {len(log_files)} file(s): ", log_files)
        all_count = 0
        attacker_ips = set()
        vmscan_ips = set()  # Collect whitelisted VMScan IPs for exclusion
        # Optionally, populate vmscan_ips by parsing trusted scanner IPs file if you have one

        def is_vmscan_ip(ip):
            # Example: treat all whitelisted IPs with 'scan' in the comment as vmscan IPs.
            # For now, just use the whitelist, but adjust as needed.
            return is_whitelisted(ip, ip_whitelist)
        
        # Centralized processing that builds both CSV and attacker IP set reliably
        csv_exists = output_csv.exists()
        existing_tx_ids = set()
        if csv_exists:
            with open(output_csv, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    existing_tx_ids.add(row.get('tx_id', ''))
        with open(output_csv, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES, quoting=csv.QUOTE_MINIMAL, extrasaction='ignore')
            if not csv_exists:
                writer.writeheader()
            def process_and_collect(lines):
                tx = parse_transaction(lines)
                if tx:
                    if tx['tx_id'] in existing_tx_ids:
                        # Skip duplicate
                        return
                    is_ip_white = is_whitelisted(tx['client_ip'], ip_whitelist)
                    is_url_white = tx['url'] in url_whitelist
                    tx['confirmed_attack'] = int(tx['anomaly_score']) >= anomaly_threshold and not (is_ip_white or is_url_white)
                    # Strict row validation: only FIELDNAMES, all present, no extra keys, ensure type safety
                    outrow = {name: '' for name in FIELDNAMES}  # Initialize all columns
                    for name in FIELDNAMES:
                        val = tx.get(name, '')
                        if isinstance(val, bool):
                            val = 'True' if val else 'False'
                        if val is None:
                            val = ''
                        outrow[name] = str(val)
                    # Optionally warn about extra columns
                    extra_keys = [k for k in tx.keys() if k not in FIELDNAMES]
                    if extra_keys:
                        print(f"Warning: Skipping extra columns not in FIELDNAMES: {extra_keys}")
                    writer.writerow(outrow)
                    existing_tx_ids.add(tx['tx_id'])
                    print(f"TX {tx['tx_id']} | IP: {tx['client_ip']} | Score {tx['anomaly_score']} | Attack: {tx['confirmed_attack']}")
                    if tx['confirmed_attack'] and is_valid_ip(tx['client_ip']) and not is_whitelisted(tx['client_ip'], ip_whitelist) and not tx['is_vm_scan']:
                        attacker_ips.add(tx['client_ip'])
            for log_path in log_files:
                blocks = parse_modsec_log(log_path)
                file_tx_count = 0
                for lines in blocks:
                    process_and_collect(lines)
                    file_tx_count += 1
                print(f"{log_path}: {file_tx_count} parsed transactions.")
                all_count += file_tx_count
        print(f"Total parsed blocks: {all_count}")
        print(f"Report written to: {output_csv}")
        # --- CREATE BLOCK SCRIPT ---
        print(f"DEBUG: {len(attacker_ips)} attacker IPs collected: {attacker_ips}")
        if attacker_ips:
            script_filename = output_dir / f"blocklist-{datetime.now().strftime('%d-%m-%Y')}.sh"
            script_filename = script_filename.resolve()  # Absolute full path
            print(f"DEBUG: Bash script will be written to: {script_filename}")
            script_exists = script_filename.exists()
            existing_ips_in_script = set()
            if script_exists:
                with open(script_filename, 'r') as f:
                    for line in f:
                        m = re.match(r'.*iptables -A INPUT -s ([0-9a-fA-F\.:]+) -j DROP', line)
                        if m:
                            existing_ips_in_script.add(m.group(1))
            with open(script_filename, 'a') as sh:
                if not script_exists:
                    sh.write('#!/bin/bash\n')
                    sh.write('echo "Parsing current firewall blocked IPs ..."\n')
                    sh.write('EXISTING_IPS=$(iptables -L INPUT -n | awk \'/DROP/ {print $4}\')\n')
                    sh.write('function ip_already_blocked {\n')
                    sh.write('    echo "$EXISTING_IPS" | grep -q "^$1$"\n')
                    sh.write('}\n')
                new_ip_writes = 0
                for ip in sorted(attacker_ips):
                    if ip in existing_ips_in_script:
                        continue
                    sh.write(f'if ! ip_already_blocked {ip}; then\n')
                    sh.write(f'    echo "Blocking {ip}"\n')
                    sh.write(f'    iptables -A INPUT -s {ip} -j DROP\n')
                    sh.write('else\n')
                    sh.write(f'    echo "{ip} already blocked, skipping."\n')
                    sh.write('fi\n')
                    new_ip_writes += 1
                sh.write('echo "Done.\n"\n')
            os.chmod(script_filename, 0o755)
            print(f"Block script generated/appended: {script_filename} (Added {new_ip_writes} new IPs)")
        else:
            print("No attacker IPs detected, block script NOT generated.")

if __name__ == '__main__':
    main()
