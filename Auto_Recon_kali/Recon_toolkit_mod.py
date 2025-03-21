#!/usr/bin/env python3

import os
import subprocess
import argparse
import time
import re
import datetime
import sys
import json
from pathlib import Path

class colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def validate_target(target):
    """Validate and format the target domain/IP."""
    # Remove protocol prefix if present
    if target.startswith(('http://', 'https://')):
        target = re.sub(r'^https?://', '', target)
    
    # Remove trailing path if present
    target = target.split('/')[0]
    
    # Basic domain/IP validation
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target) and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        print(f"{colors.FAIL}[!] Invalid target format. Please provide a valid domain or IP.{colors.ENDC}")
        sys.exit(1)
    
    return target

def create_output_directory(target):
    """Create an output directory for scan results."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"recon_{target.replace('.', '_')}_{timestamp}"
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"{colors.GREEN}[+] Created output directory: {output_dir}{colors.ENDC}")
        return output_dir
    except Exception as e:
        print(f"{colors.FAIL}[!] Error creating output directory: {str(e)}{colors.ENDC}")
        sys.exit(1)

def check_tools_installed():
    """Check if required tools are installed."""
    tools = ['nmap', 'gobuster', 'theHarvester']
    missing_tools = []
    
    for tool in tools:
        try:
            subprocess.run(['which', tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{colors.FAIL}[!] The following required tools are not installed: {', '.join(missing_tools)}{colors.ENDC}")
        print(f"{colors.WARNING}[*] Install them using: sudo apt-get install {' '.join(missing_tools)}{colors.ENDC}")
        sys.exit(1)

def run_nmap(target, output_dir):
    """Run Nmap scan on target with full port scanning capability."""
    print(f"\n{colors.HEADER}{colors.BOLD}[+] Running Nmap scan on {target}...{colors.ENDC}")
    
    # Define output files
    xml_output = os.path.join(output_dir, f"nmap_scan_{target}.xml")
    txt_output = os.path.join(output_dir, f"nmap_scan_{target}.txt")
    all_ports_output = os.path.join(output_dir, f"nmap_all_ports_{target}.txt")
    
    try:
        # Step 1: Run a full TCP port scan on all 65535 ports
        print(f"{colors.BLUE}[*] Starting full port scan (1-65535). This will take some time...{colors.ENDC}")
        
        full_port_cmd = [
            'nmap', '-p-', '--min-rate=1000', '-T4', '--open', 
            '-oN', all_ports_output, target
        ]
        
        print(f"{colors.BLUE}[*] Executing: {' '.join(full_port_cmd)}{colors.ENDC}")
        subprocess.run(full_port_cmd, check=True)
        
        # Step 2: Parse the output to find open ports
        open_ports = []
        try:
            with open(all_ports_output, 'r') as f:
                content = f.read()
                # Extract ports using regex
                port_matches = re.findall(r'(\d+)/tcp\s+open', content)
                if port_matches:
                    open_ports = port_matches
        except Exception as e:
            print(f"{colors.WARNING}[!] Error parsing port scan results: {str(e)}{colors.ENDC}")
        
        if not open_ports:
            print(f"{colors.WARNING}[!] No open ports found. Running default scan instead.{colors.ENDC}")
            # Run a default scan if no ports found
            default_cmd = [
                'nmap', '-sV', '-sC', '--open', '-oN', txt_output, '-oX', xml_output, target
            ]
            print(f"{colors.BLUE}[*] Executing: {' '.join(default_cmd)}{colors.ENDC}")
            subprocess.run(default_cmd, check=True)
        else:
            # Step 3: Run a detailed scan on the open ports only
            ports_str = ','.join(open_ports)
            print(f"{colors.GREEN}[+] Found {len(open_ports)} open ports: {ports_str}{colors.ENDC}")
            
            detailed_cmd = [
                'nmap', '-p', ports_str, '-sV', '-sC', '--open',
                '-oN', txt_output, '-oX', xml_output, target
            ]
            
            print(f"{colors.BLUE}[*] Executing detailed scan on open ports...{colors.ENDC}")
            print(f"{colors.BLUE}[*] Command: {' '.join(detailed_cmd)}{colors.ENDC}")
            subprocess.run(detailed_cmd, check=True)
        
        # Step 4: Check if web ports are open for more targeted scanning
        web_ports_found = False
        common_web_ports = ['80', '443', '8080', '8443', '3000', '8000', '8008', '8800']
        detected_web_ports = []
        
        with open(txt_output, 'r') as f:
            content = f.read()
            for port in common_web_ports:
                if f'{port}/tcp' in content:
                    detected_web_ports.append(port)
                    web_ports_found = True
        
        if web_ports_found:
            web_ports_str = ','.join(detected_web_ports)
            print(f"{colors.GREEN}[+] Web ports detected ({web_ports_str}), running HTTP service scan...{colors.ENDC}")
            http_scan_output = os.path.join(output_dir, f"nmap_http_scan_{target}.txt")
            http_cmd = [
                'nmap', '-p', web_ports_str, 
                '--script=http-title,http-headers,http-methods,http-enum', 
                '-oN', http_scan_output, target
            ]
            print(f"{colors.BLUE}[*] Executing: {' '.join(http_cmd)}{colors.ENDC}")
            subprocess.run(http_cmd, check=True)
        
        print(f"{colors.GREEN}[+] Nmap scan completed. Results saved to {txt_output}{colors.ENDC}")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"{colors.FAIL}[!] Error running Nmap: {str(e)}{colors.ENDC}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"{colors.FAIL}[!] Error details: {e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr}{colors.ENDC}")
        return False
    except Exception as e:
        print(f"{colors.FAIL}[!] Unexpected error during Nmap scan: {str(e)}{colors.ENDC}")
        return False

def run_gobuster(target, output_dir, wordlist=None):
    """Run Gobuster scan on target."""
    print(f"\n{colors.HEADER}{colors.BOLD}[+] Running Gobuster directory scan on {target}...{colors.ENDC}")
    
    # Use default wordlist if none provided
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        # Check if directory-list-2.3-medium.txt exists (better wordlist)
        medium_list = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if os.path.exists(medium_list):
            wordlist = medium_list
    
    # Check if wordlist exists
    if not os.path.exists(wordlist):
        print(f"{colors.WARNING}[!] Wordlist not found: {wordlist}. Falling back to /usr/share/wordlists/dirb/common.txt{colors.ENDC}")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        if not os.path.exists(wordlist):
            print(f"{colors.FAIL}[!] Default wordlist not found. Please install wordlists with: sudo apt-get install wordlists{colors.ENDC}")
            return False
    
    output_file = os.path.join(output_dir, f"gobuster_scan_{target}.txt")
    
    try:
        # First attempt with standard options - using ONLY status codes (not blacklist)
        cmd = [
            'gobuster', 'dir', 
            '-u', f"http://{target}", 
            '-w', wordlist,
            '-o', output_file,
            '-t', '50',  # threads
            '-s', '200,204,301,302,307,401,403'  # status codes to show
        ]
        
        print(f"{colors.BLUE}[*] Executing: {' '.join(cmd)}{colors.ENDC}")
        print(f"{colors.WARNING}[*] This might take some time depending on the wordlist size...{colors.ENDC}")
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if hasattr(e, 'stderr') else ""
            
            # Check if it's a status code related error
            if "status-codes" in error_msg and "status-codes-blacklist" in error_msg:
                print(f"{colors.WARNING}[!] Status code parameter issue. Retrying with only blacklist option...{colors.ENDC}")
                cmd = [
                    'gobuster', 'dir', 
                    '-u', f"http://{target}", 
                    '-w', wordlist,
                    '-o', output_file,
                    '-t', '50',  # threads
                    '-b', '404'  # only use blacklist
                ]
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as e2:
                    # If that also fails, try with follow-redirects
                    if "Error: the server returns a status code that matches" in (e2.stderr or ""):
                        print(f"{colors.WARNING}[!] Blacklist approach failed. Retrying with --follow-redirects...{colors.ENDC}")
                        cmd.append('--follow-redirects')
                        try:
                            subprocess.run(cmd, check=True)
                        except subprocess.CalledProcessError:
                            # Last attempt: exclude-length
                            length_match = re.search(r'Length: (\d+)', e2.stderr or "")
                            if length_match:
                                length = length_match.group(1)
                                print(f"{colors.WARNING}[!] Trying one last approach with --exclude-length {length}...{colors.ENDC}")
                                cmd = [
                                    'gobuster', 'dir', 
                                    '-u', f"http://{target}", 
                                    '-w', wordlist,
                                    '-o', output_file,
                                    '-t', '50',
                                    '--exclude-length', length
                                ]
                                subprocess.run(cmd, check=True)
                            else:
                                raise
                    else:
                        raise
            elif "Error: the server returns a status code that matches" in error_msg:
                # Try with exclude-length if it's in the error message
                length_match = re.search(r'Length: (\d+)', error_msg)
                if length_match:
                    length = length_match.group(1)
                    print(f"{colors.WARNING}[!] Retrying with --exclude-length {length} option...{colors.ENDC}")
                    cmd = [
                        'gobuster', 'dir', 
                        '-u', f"http://{target}", 
                        '-w', wordlist,
                        '-o', output_file,
                        '-t', '50',
                        '--exclude-length', length
                    ]
                    subprocess.run(cmd, check=True)
                else:
                    raise
            else:
                raise
        
        print(f"{colors.GREEN}[+] Gobuster scan completed. Results saved to {output_file}{colors.ENDC}")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"{colors.FAIL}[!] Error running Gobuster: {str(e)}{colors.ENDC}")
        if hasattr(e, 'stderr') and e.stderr:
            error_text = e.stderr if isinstance(e.stderr, str) else e.stderr.decode()
            print(f"{colors.FAIL}[!] Error details: {error_text}{colors.ENDC}")
        return False
    except Exception as e:
        print(f"{colors.FAIL}[!] Unexpected error during Gobuster scan: {str(e)}{colors.ENDC}")
        return False

def run_theharvester(target, output_dir):
    """Run theHarvester on target."""
    print(f"\n{colors.HEADER}{colors.BOLD}[+] Running theHarvester on {target}...{colors.ENDC}")
    
    output_file = os.path.join(output_dir, f"theharvester_{target}.txt")
    json_output = os.path.join(output_dir, f"theharvester_{target}.json")
    
    try:
        # Run theHarvester with multiple data sources
        cmd = [
            'theHarvester', 
            '-d', target,
            '-b', 'all',  # Use all available data sources
            '-f', json_output,  # JSON output
        ]
        
        print(f"{colors.BLUE}[*] Executing: {' '.join(cmd)}{colors.ENDC}")
        
        # Capture output for text file
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Save the output to text file
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        
        print(f"{colors.GREEN}[+] theHarvester scan completed. Results saved to {output_file} and {json_output}{colors.ENDC}")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"{colors.FAIL}[!] Error running theHarvester: {str(e)}{colors.ENDC}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"{colors.FAIL}Error details: {e.stderr}{colors.ENDC}")
        return False
    except Exception as e:
        print(f"{colors.FAIL}[!] Unexpected error during theHarvester scan: {str(e)}{colors.ENDC}")
        return False

def generate_report(target, output_dir, results):
    """Generate a summary report."""
    report_file = os.path.join(output_dir, f"recon_summary_{target}.txt")
    
    try:
        with open(report_file, 'w') as f:
            f.write(f"Reconnaissance Summary for {target}\n")
            f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            # Summary of scans
            f.write("Scan Summary:\n")
            for tool, status in results.items():
                status_text = "Completed" if status else "Failed"
                f.write(f"- {tool}: {status_text}\n")
            
            f.write("\n" + "=" * 50 + "\n\n")
            
            # Nmap summary if available
            nmap_file = os.path.join(output_dir, f"nmap_scan_{target}.txt")
            if os.path.exists(nmap_file):
                f.write("NMAP OPEN PORTS AND SERVICES:\n")
                with open(nmap_file, 'r') as nmap_f:
                    content = nmap_f.read()
                    # Extract open ports section
                    if "PORT" in content and "SERVICE" in content:
                        port_section = re.search(r'PORT.*?SERVICE.*?\n(.*?)^\n', content, re.DOTALL | re.MULTILINE)
                        if port_section:
                            f.write(port_section.group(1) + "\n\n")
            
            # Gobuster summary if available
            gobuster_file = os.path.join(output_dir, f"gobuster_scan_{target}.txt")
            if os.path.exists(gobuster_file):
                f.write("GOBUSTER DISCOVERED DIRECTORIES:\n")
                with open(gobuster_file, 'r') as gobuster_f:
                    # Only include the first 20 findings to keep the summary concise
                    lines = gobuster_f.readlines()[:20]
                    f.write(''.join(lines) + "\n")
                if len(lines) >= 20:
                    f.write(f"... (more results in {gobuster_file})\n\n")
            
            # theHarvester summary if available - using the JSON file for better parsing
            harvester_json = os.path.join(output_dir, f"theharvester_{target}.json")
            if os.path.exists(harvester_json):
                try:
                    with open(harvester_json, 'r') as harvest_f:
                        data = json.load(harvest_f)
                        
                        f.write("THEHARVESTER FINDINGS:\n")
                        
                        # Extract emails if available
                        if "emails" in data and data["emails"]:
                            f.write("- Emails found:\n")
                            for email in data["emails"][:10]:  # Limit to first 10
                                f.write(f"  * {email}\n")
                            if len(data["emails"]) > 10:
                                f.write(f"  * ... and {len(data['emails']) - 10} more\n")
                        
                        # Extract hosts if available
                        if "hosts" in data and data["hosts"]:
                            f.write("- Hosts found:\n")
                            for host in data["hosts"][:10]:  # Limit to first 10
                                f.write(f"  * {host}\n")
                            if len(data["hosts"]) > 10:
                                f.write(f"  * ... and {len(data['hosts']) - 10} more\n")
                except:
                    # Fallback to text file if JSON parsing fails
                    harvester_txt = os.path.join(output_dir, f"theharvester_{target}.txt")
                    if os.path.exists(harvester_txt):
                        f.write("THEHARVESTER FINDINGS (see full file for details):\n")
                        with open(harvester_txt, 'r') as harvest_txt:
                            content = harvest_txt.read()
                            # Extract just email addresses for the summary
                            emails = re.findall(r'[\w\.-]+@[\w\.-]+', content)
                            if emails:
                                f.write("- Emails found:\n")
                                for email in set(emails)[:10]:  # Limit to first 10 unique
                                    f.write(f"  * {email}\n")
            
            f.write("\n" + "=" * 50 + "\n")
            f.write(f"Full scan results are available in the {output_dir} directory.\n")
        
        print(f"{colors.GREEN}[+] Summary report generated: {report_file}{colors.ENDC}")
        return True
    
    except Exception as e:
        print(f"{colors.FAIL}[!] Error generating report: {str(e)}{colors.ENDC}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Kali Linux Automated Reconnaissance Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist for Gobuster')
    parser.add_argument('--skip-nmap', action='store_true', help='Skip Nmap scan')
    parser.add_argument('--skip-gobuster', action='store_true', help='Skip Gobuster scan')
    parser.add_argument('--skip-harvester', action='store_true', help='Skip theHarvester scan')
    parser.add_argument('--quick', action='store_true', help='Run a quicker scan (skip full port scan)')
    
    args = parser.parse_args()
    
    print(f"{colors.BOLD}{colors.HEADER}================================{colors.ENDC}")
    print(f"{colors.BOLD}{colors.HEADER}= Kali Reconnaissance Toolkit ={colors.ENDC}")
    print(f"{colors.BOLD}{colors.HEADER}================================{colors.ENDC}\n")
    
    # Check for root privileges
    if os.geteuid() != 0:
        print(f"{colors.WARNING}[!] Warning: Some scans may require root privileges. Consider running with sudo.{colors.ENDC}")
    
    # Validate target
    target = validate_target(args.target)
    
    # Check if required tools are installed
    check_tools_installed()
    
    # Create output directory
    output_dir = create_output_directory(target)
    
    # Track scan results
    results = {
        "Nmap": False,
        "Gobuster": False,
        "theHarvester": False
    }
    
    # Run the tools
    start_time = time.time()
    
    if not args.skip_nmap:
        if args.quick:
            print(f"{colors.WARNING}[*] Running quick Nmap scan (limited port scan){colors.ENDC}")
            # Original implementation here if needed
        else:
            print(f"{colors.WARNING}[*] Running complete Nmap scan of all 65535 ports - this will take significant time{colors.ENDC}")
        
        results["Nmap"] = run_nmap(target, output_dir)
    else:
        print(f"{colors.WARNING}[*] Nmap scan skipped as requested{colors.ENDC}")
    
    if not args.skip_gobuster:
        results["Gobuster"] = run_gobuster(target, output_dir, args.wordlist)
    else:
        print(f"{colors.WARNING}[*] Gobuster scan skipped as requested{colors.ENDC}")
    
    if not args.skip_harvester:
        results["theHarvester"] = run_theharvester(target, output_dir)
    else:
        print(f"{colors.WARNING}[*] theHarvester scan skipped as requested{colors.ENDC}")
    
    # Generate summary report
    generate_report(target, output_dir, results)
    
    # Calculate and display total execution time
    end_time = time.time()
    duration = end_time - start_time
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    print(f"\n{colors.GREEN}{colors.BOLD}[+] Reconnaissance completed in {int(hours):02}:{int(minutes):02}:{int(seconds):02}{colors.ENDC}")
    print(f"{colors.GREEN}[+] All results saved to {output_dir}/{colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{colors.WARNING}[!] Scan interrupted by user. Exiting...{colors.ENDC}")
        sys.exit(1)