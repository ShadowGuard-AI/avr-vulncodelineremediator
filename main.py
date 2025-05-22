import argparse
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup
import ast
import difflib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class VulnerabilityDatabaseError(Exception):
    """Custom exception for vulnerability database errors."""
    pass


class CodeAnalysisError(Exception):
    """Custom exception for code analysis errors."""
    pass


class PatchGenerationError(Exception):
    """Custom exception for patch generation errors."""
    pass


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="avr-VulnCodeLineRemediator: Automated Vulnerability Remediation Tool"
    )

    parser.add_argument(
        "--vulnerability_id",
        type=str,
        required=True,
        help="The ID of the vulnerability to remediate (e.g., CVE-2023-1234)",
    )
    parser.add_argument(
        "--codebase_path",
        type=str,
        required=True,
        help="The path to the codebase to scan.",
    )
    parser.add_argument(
        "--output_patch_path",
        type=str,
        default="patch.diff",
        help="The path to save the generated patch file. Defaults to 'patch.diff'.",
    )
    parser.add_argument(
        "--approval_required",
        action="store_true",
        help="Require manual approval before applying changes (interactive mode).",
    )
    parser.add_argument(
        "--exploit_db_url",
        type=str,
        default="https://www.exploit-db.com/",
        help="The base URL of the Exploit Database to use for vulnerability information.",
    )

    return parser


def fetch_vulnerability_data(vulnerability_id: str, exploit_db_url: str) -> Tuple[str, str]:
    """
    Fetches vulnerability data from a vulnerability database (e.g., Exploit Database).
    Parses the HTML content to extract relevant information, such as the vulnerability description
    and potential exploit code snippets.

    Args:
        vulnerability_id (str): The ID of the vulnerability (e.g., CVE-2023-1234).
        exploit_db_url (str): The base URL of the Exploit Database.

    Returns:
        Tuple[str, str]: A tuple containing the vulnerability description and exploit details (or None if not found).

    Raises:
        VulnerabilityDatabaseError: If an error occurs while fetching or parsing the data.
    """
    try:
        # Construct the URL for the vulnerability based on the database format.
        search_url = f"{exploit_db_url}search?value={vulnerability_id}"
        logging.info(f"Fetching vulnerability data from: {search_url}")

        response = requests.get(search_url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")

        # Example parsing: Adjust selectors based on the actual structure of the database page.
        vulnerability_description = ""
        exploit_details = ""
        
        # Find the first table on the page
        table = soup.find("table")
        if table:
            # Find all rows in the table
            rows = table.find_all("tr")
            
            # Iterate through the rows and extract data from the first column (<td>)
            for row in rows:
                cells = row.find_all("td")
                if cells:
                    # Extract the text from the first cell
                    cell_text = cells[0].get_text(strip=True)
                    vulnerability_description = cell_text  # This may need more precise selection
                    
                    # Attempt to extract exploit details (this will vary based on the database)
                    # This is a placeholder and needs to be adjusted for a real database structure
                    exploit_details = row.find("div", class_="code").get_text(strip=True) if row.find("div", class_="code") else ""
                    break # Stop after processing the first row
        
        if not vulnerability_description:
            logging.warning(f"No vulnerability information found for ID: {vulnerability_id}")
            return None, None

        return vulnerability_description, exploit_details

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching vulnerability data: {e}")
        raise VulnerabilityDatabaseError(f"Failed to fetch vulnerability data: {e}")
    except Exception as e:
        logging.error(f"Error parsing vulnerability data: {e}")
        raise VulnerabilityDatabaseError(f"Failed to parse vulnerability data: {e}")


def identify_vulnerable_code_lines(
    codebase_path: str, vulnerability_description: str, exploit_details: str
) -> List[Tuple[str, int]]:
    """
    Identifies vulnerable code lines in the codebase based on the vulnerability description
    and exploit details.  Uses AST to parse the code and identify potentially vulnerable blocks.
    This is a simplified example; a real implementation would require more sophisticated analysis.

    Args:
        codebase_path (str): The path to the codebase.
        vulnerability_description (str): The vulnerability description.
        exploit_details (str): The exploit details.

    Returns:
        List[Tuple[str, int]]: A list of tuples, where each tuple contains the filename and line number
                                 of a vulnerable code line.

    Raises:
        CodeAnalysisError: If an error occurs during code analysis.
    """
    vulnerable_lines = []
    try:
        for root, _, files in os.walk(codebase_path):
            for file in files:
                if file.endswith(".py"):  # Analyze Python files
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            code = f.read()
                            tree = ast.parse(code)

                            # Simple heuristic: Check for lines containing keywords from the vulnerability description or exploit
                            keywords = re.split(r'\W+', vulnerability_description + " " + exploit_details)
                            keywords = [k.lower() for k in keywords if k]

                            for node in ast.walk(tree):
                                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                                    for lineno in range(node.lineno, getattr(node, 'end_lineno', node.lineno) + 1 if hasattr(node, 'end_lineno') else node.lineno + 1):
                                        try:
                                            line = linecache.getline(filepath, lineno).strip().lower() # Linecache
                                            if any(keyword in line for keyword in keywords):
                                                vulnerable_lines.append((filepath, lineno))
                                        except Exception as le:
                                            logging.warning(f"Error accessing line {lineno} in {filepath}: {le}")


                    except Exception as e:
                        logging.error(f"Error analyzing file {filepath}: {e}")
                        continue  # Move to the next file

    except Exception as e:
        logging.error(f"Error during code analysis: {e}")
        raise CodeAnalysisError(f"Failed to analyze codebase: {e}")

    return vulnerable_lines

import linecache

def suggest_fixes(filepath: str, vulnerable_line_number: int, vulnerability_description: str, exploit_details: str) -> str:
    """
    Suggests a fix for a vulnerable line of code based on the vulnerability description and exploit details.
    This is a placeholder implementation; a real implementation would use more sophisticated techniques
    like pattern matching, code transformation, or calls to external security analysis tools.

    Args:
        filepath (str): The path to the file containing the vulnerable line.
        vulnerable_line_number (int): The line number of the vulnerable line.
        vulnerability_description (str): The vulnerability description.
        exploit_details (str): The exploit details.

    Returns:
        str: The suggested fix for the vulnerable line.  Returns an empty string if no fix is suggested.

    """

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if 1 <= vulnerable_line_number <= len(lines):
                vulnerable_line = lines[vulnerable_line_number - 1]

                # Placeholder: Suggest a fix based on simple keyword replacement
                if "input(" in vulnerable_line.lower():
                    suggested_fix = vulnerable_line.replace("input(", "getpass.getpass(") # import getpass must be manually added

                elif "os.system(" in vulnerable_line.lower():
                    suggested_fix = "# WARNING: os.system is a security risk, replace with subprocess.run\n" + vulnerable_line # User needs to manually implement

                elif "pickle.load(" in vulnerable_line.lower():
                    suggested_fix = "# WARNING: pickle.load can load malicious data. Replace with a safer serializer such as json.loads \n" + vulnerable_line # User needs to manually implement
                else:
                    suggested_fix = ""  # No fix suggestion

                return suggested_fix.rstrip('\n')  # remove trailing newline.

            else:
                logging.warning(f"Vulnerable line number {vulnerable_line_number} is out of range for file {filepath}")
                return ""  # Line number out of range.


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return ""
    except Exception as e:
        logging.error(f"Error generating fix: {e}")
        return ""



def generate_patch(filepath: str, vulnerable_line_number: int, suggested_fix: str) -> str:
    """
    Generates a patch file that applies the suggested fix to the vulnerable code.
    Uses the 'diff' command to create a unified diff format patch.

    Args:
        filepath (str): The path to the file to be patched.
        vulnerable_line_number (int): The line number of the vulnerable line.
        suggested_fix (str): The suggested fix for the vulnerable line.

    Returns:
        str: The content of the generated patch file.

    Raises:
        PatchGenerationError: If an error occurs during patch generation.
    """
    try:
        # Create a temporary file with the original code.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp") as original_file:
            with open(filepath, "r", encoding="utf-8") as f:
                original_code = f.readlines()
                original_file.writelines(original_code)
            original_file_path = original_file.name

        # Create a temporary file with the modified code.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp") as modified_file:
            modified_code = original_code[:]  # Copy original code
            if 1 <= vulnerable_line_number <= len(modified_code):
                modified_code[vulnerable_line_number - 1] = suggested_fix + "\n"
            else:
                logging.warning(f"Vulnerable line number {vulnerable_line_number} is out of range for file {filepath}")
                return ""

            modified_file.writelines(modified_code)
            modified_file_path = modified_file.name

        # Generate the diff using difflib
        with open(filepath, "r", encoding="utf-8") as f:
          original_lines = f.readlines()

        with open(modified_file_path, "r", encoding="utf-8") as f:
          modified_lines = f.readlines()

        diff = difflib.unified_diff(original_lines, modified_lines, fromfile=filepath, tofile=filepath)
        patch_content = ''.join(diff)

        # Clean up temporary files
        os.remove(original_file_path)
        os.remove(modified_file_path)

        return patch_content

    except Exception as e:
        logging.error(f"Error generating patch: {e}")
        raise PatchGenerationError(f"Failed to generate patch: {e}")


def apply_patch(filepath: str, patch_content: str) -> None:
    """
    Applies a patch file to a file.  Uses the 'patch' command to apply the changes.

    Args:
        filepath (str): The path to the file to be patched.
        patch_content (str): The content of the patch file.

    Raises:
        PatchGenerationError: If an error occurs while applying the patch.
    """
    try:
        # Write the patch content to a temporary file.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".patch") as patch_file:
            patch_file.write(patch_content)
            patch_file_path = patch_file.name

        # Apply the patch using the 'patch' command.
        command = ["patch", "-u", filepath, patch_file_path]
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logging.error(f"Error applying patch: {result.stderr}")
            raise PatchGenerationError(f"Failed to apply patch: {result.stderr}")

        logging.info(f"Patch applied successfully to {filepath}")

        # Clean up the temporary patch file.
        os.remove(patch_file_path)

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise PatchGenerationError(f"File not found: {e}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error applying patch: {e.stderr}")
        raise PatchGenerationError(f"Failed to apply patch: {e.stderr}")
    except Exception as e:
        logging.error(f"Error applying patch: {e}")
        raise PatchGenerationError(f"Failed to apply patch: {e}")


def main():
    """
    Main function to orchestrate the vulnerability remediation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # 1. Fetch vulnerability data from the database.
        vulnerability_description, exploit_details = fetch_vulnerability_data(
            args.vulnerability_id, args.exploit_db_url
        )

        if not vulnerability_description:
            logging.error(f"Vulnerability with ID '{args.vulnerability_id}' not found.")
            sys.exit(1)


        # 2. Identify vulnerable code lines.
        vulnerable_lines = identify_vulnerable_code_lines(
            args.codebase_path, vulnerability_description, exploit_details
        )

        if not vulnerable_lines:
            logging.info("No vulnerable code lines found.")
            sys.exit(0)

        logging.info(f"Found {len(vulnerable_lines)} potentially vulnerable lines.")


        # 3. Generate and optionally apply patches.
        all_patches = ""
        for filepath, line_number in vulnerable_lines:
            # Suggest a fix.
            suggested_fix = suggest_fixes(filepath, line_number, vulnerability_description, exploit_details)

            if suggested_fix:
                logging.info(f"Suggested fix: {suggested_fix}")
                # Generate a patch.
                patch_content = generate_patch(filepath, line_number, suggested_fix)

                if patch_content:
                    print(f"Generated patch:\n{patch_content}")
                    all_patches += patch_content
                    if args.approval_required:
                        approval = input(f"Apply patch to {filepath} (y/n)? ").lower()
                        if approval == "y":
                            apply_patch(filepath, patch_content)
                        else:
                            logging.info(f"Patch for {filepath} not applied.")
                    else:
                        apply_patch(filepath, patch_content)
                else:
                    logging.warning(f"No patch generated for {filepath}:{line_number}")
            else:
                logging.warning(f"No fix suggested for {filepath}:{line_number}")
        
        # Save all patches to a single file if there are patches to save
        if all_patches:
            with open(args.output_patch_path, "w", encoding="utf-8") as f:
                f.write(all_patches)
            logging.info(f"All generated patches saved to {args.output_patch_path}")


    except VulnerabilityDatabaseError as e:
        logging.error(f"Vulnerability database error: {e}")
        sys.exit(1)
    except CodeAnalysisError as e:
        logging.error(f"Code analysis error: {e}")
        sys.exit(1)
    except PatchGenerationError as e:
        logging.error(f"Patch generation error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


"""
Usage Examples:

1.  Run the tool to identify and remediate a vulnerability in a codebase, requiring manual approval before applying changes:

    python avr_vulncode_line_remediator.py --vulnerability_id CVE-2023-4567 --codebase_path /path/to/codebase --approval_required

2.  Run the tool without manual approval, automatically applying the generated patches:

    python avr_vulncode_line_remediator.py --vulnerability_id CVE-2023-4567 --codebase_path /path/to/codebase

3.  Specify a custom output path for the generated patch file:

    python avr_vulncode_line_remediator.py --vulnerability_id CVE-2023-4567 --codebase_path /path/to/codebase --output_patch_path my_patch.diff

4. Specify a custom Exploit Database URL:
    python avr_vulncode_line_remediator.py --vulnerability_id CVE-2023-4567 --codebase_path /path/to/codebase --exploit_db_url https://example.com/exploitdb/
"""